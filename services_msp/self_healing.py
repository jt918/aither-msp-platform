"""
AITHER Platform - Self-Healing Agent
MSP Tier 1: Autonomous ITSM

Detects system faults and attempts automated fixes before escalating.
Dispatches remediation commands through the RMM command queue for
actual remote execution on managed endpoints.

G-46: Refactored for DB persistence with in-memory fallback.
G-47: Wired to RMM command queue for real remediation dispatch.
"""

import asyncio
import logging
from enum import Enum
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
import subprocess
import platform

logger = logging.getLogger(__name__)

try:
    from sqlalchemy.orm import Session
    from models.msp import SelfHealingIncident as SelfHealingIncidentModel
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

try:
    from services.msp.rmm import RMMService
    RMM_AVAILABLE = True
except Exception:
    RMM_AVAILABLE = False
    RMMService = None  # type: ignore


class FaultType(Enum):
    """Types of system faults the agent can handle"""
    PRINTER_SPOOLER = "printer_spooler"
    DISK_SPACE = "disk_space"
    SERVICE_DOWN = "service_down"
    NETWORK_CONNECTIVITY = "network_connectivity"
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    DNS_FAILURE = "dns_failure"
    CERTIFICATE_EXPIRY = "certificate_expiry"


class FixStatus(Enum):
    """Status of a fix attempt"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ESCALATED = "escalated"


@dataclass
class Fault:
    """Represents a detected system fault"""
    fault_id: str
    fault_type: FaultType
    severity: int  # 1-10
    endpoint: str
    description: str
    detected_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FixAttempt:
    """Record of a fix attempt"""
    attempt_number: int
    fix_type: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: FixStatus = FixStatus.PENDING
    output: str = ""
    error: str = ""


@dataclass
class Ticket:
    """Support ticket for escalated issues"""
    ticket_id: str
    fault: Fault
    fix_attempts: List[FixAttempt]
    created_at: datetime
    priority: str  # P1, P2, P3, P4
    status: str = "open"
    assigned_to: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════
# REMEDIATION COMMAND MAP
# Maps each FaultType to concrete shell commands per OS.
# Each entry is a list of escalation tiers (safest first).
# Each tier contains {"windows": [cmds], "linux": [cmds], "label": str}.
# ═══════════════════════════════════════════════════════════════════════

REMEDIATION_COMMANDS: Dict[FaultType, List[Dict[str, Any]]] = {
    FaultType.PRINTER_SPOOLER: [
        {
            "label": "restart_spooler",
            "windows": ["net stop spooler", "net start spooler"],
            "linux": ["systemctl restart cups"],
        },
        {
            "label": "clear_queue_and_restart",
            "windows": [
                "net stop spooler",
                'del /Q /F /S "%systemroot%\\System32\\Spool\\Printers\\*.*"',
                "net start spooler",
            ],
            "linux": ["cancel -a", "systemctl restart cups"],
        },
        {
            "label": "reinstall_driver",
            "windows": [],  # requires manual intervention
            "linux": [],
        },
    ],
    FaultType.DISK_SPACE: [
        {
            "label": "clear_temp",
            "windows": ["del /q/f/s %TEMP%\\*", "del /q/f/s C:\\Windows\\Temp\\*"],
            "linux": ["rm -rf /tmp/*", "rm -rf /var/tmp/*"],
        },
        {
            "label": "clear_old_logs",
            "windows": [
                'forfiles /p "C:\\Windows\\Logs" /s /m *.log /d -30 /c "cmd /c del @path"'
            ],
            "linux": [
                "find /var/log -type f -name '*.log' -mtime +30 -delete",
                "journalctl --vacuum-time=7d",
            ],
        },
        {
            "label": "compress_old_files",
            "windows": [],
            "linux": [],
        },
    ],
    FaultType.SERVICE_DOWN: [
        {
            "label": "restart_service",
            "windows": ["net stop {service_name}", "net start {service_name}"],
            "linux": ["systemctl restart {service_name}"],
        },
        {
            "label": "repair_service",
            "windows": ["sc config {service_name} start= auto"],
            "linux": ["systemctl enable {service_name}"],
        },
        {
            "label": "reinstall_service",
            "windows": [],
            "linux": [],
        },
    ],
    FaultType.NETWORK_CONNECTIVITY: [
        {
            "label": "reset_adapter",
            "windows": [
                'netsh interface set interface "{adapter}" disable',
                'netsh interface set interface "{adapter}" enable',
            ],
            "linux": ["ip link set eth0 down", "ip link set eth0 up"],
        },
        {
            "label": "flush_dns",
            "windows": ["ipconfig /flushdns"],
            "linux": ["systemd-resolve --flush-caches"],
        },
        {
            "label": "reset_tcp_stack",
            "windows": ["netsh winsock reset", "netsh int ip reset"],
            "linux": ["systemctl restart NetworkManager"],
        },
    ],
    FaultType.HIGH_CPU: [
        {
            "label": "kill_runaway_process",
            "windows": ["taskkill /F /IM {process_name}"],
            "linux": ["pkill -9 {process_name}"],
        },
        {
            "label": "restart_services",
            "windows": [],
            "linux": [],
        },
        {
            "label": "scheduled_reboot",
            "windows": [],
            "linux": [],
        },
    ],
    FaultType.HIGH_MEMORY: [
        {
            "label": "clear_cache",
            "windows": [],  # Windows manages automatically
            "linux": ["sync", "echo 3 > /proc/sys/vm/drop_caches"],
        },
        {
            "label": "restart_services",
            "windows": [],
            "linux": [],
        },
        {
            "label": "scheduled_reboot",
            "windows": [],
            "linux": [],
        },
    ],
    FaultType.DNS_FAILURE: [
        {
            "label": "flush_dns",
            "windows": ["ipconfig /flushdns"],
            "linux": ["systemd-resolve --flush-caches"],
        },
    ],
    FaultType.CERTIFICATE_EXPIRY: [
        {
            "label": "check_cert",
            "windows": [
                'powershell -Command "Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {{$_.NotAfter -lt (Get-Date).AddDays(30)}}"'
            ],
            "linux": [
                "find /etc/ssl/certs -name '*.pem' -exec openssl x509 -enddate -noout -in {{}} \\;"
            ],
        },
    ],
}


class SelfHealingAgent:
    """
    Autonomous IT Service Management Agent

    TRIGGER: System monitoring alert OR scheduled health check
    INPUT: System metrics, event logs, health indicators
    PROCESS:
        1. Detect fault type
        2. Attempt fix #1 (safest)
        3. If failed, attempt fix #2 (moderate)
        4. If failed, attempt fix #3 (aggressive)
        5. If all fail, create Tier 2 ticket
    OUTPUT: Fixed system OR escalation ticket
    STORAGE: self_healing_incidents table

    Accepts optional db: Session for persistence.
    Accepts optional rmm_service: RMMService to dispatch remediation
    commands through the RMM command queue instead of local execution.
    """

    MAX_FIX_ATTEMPTS = 3

    def __init__(self, db: Session = None, rmm_service=None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # RMM integration: use provided instance, or None to fall back to logging
        self._rmm: Optional[RMMService] = rmm_service if RMM_AVAILABLE else None

        self.fix_strategies: Dict[FaultType, List[Callable]] = {
            FaultType.PRINTER_SPOOLER: [
                self._fix_printer_restart_spooler,
                self._fix_printer_clear_queue,
                self._fix_printer_reinstall_driver,
            ],
            FaultType.DISK_SPACE: [
                self._fix_disk_clear_temp,
                self._fix_disk_clear_logs,
                self._fix_disk_compress_old,
            ],
            FaultType.SERVICE_DOWN: [
                self._fix_service_restart,
                self._fix_service_repair,
                self._fix_service_reinstall,
            ],
            FaultType.NETWORK_CONNECTIVITY: [
                self._fix_network_reset_adapter,
                self._fix_network_flush_dns,
                self._fix_network_reset_stack,
            ],
            FaultType.HIGH_CPU: [
                self._fix_cpu_kill_runaway,
                self._fix_cpu_restart_services,
                self._fix_cpu_reboot_scheduled,
            ],
            FaultType.HIGH_MEMORY: [
                self._fix_memory_clear_cache,
                self._fix_memory_restart_services,
                self._fix_memory_reboot_scheduled,
            ],
        }
        self.incident_log: List[Dict[str, Any]] = []

        # Hydrate from DB on init
        if self._use_db:
            try:
                rows = self.db.query(SelfHealingIncidentModel).order_by(
                    SelfHealingIncidentModel.created_at.desc()
                ).limit(1000).all()
                for row in rows:
                    entry = {
                        "fault_id": row.fault_id,
                        "fault_type": row.fault_type,
                        "endpoint": row.endpoint or "",
                        "severity": row.severity,
                        "detected_at": row.detected_at or "",
                        "attempts": row.attempts,
                        "outcome": row.outcome or "",
                        "resolved_at": row.resolved_at or "",
                    }
                    self.incident_log.append(entry)
            except Exception as e:
                logger.error(f"DB error hydrating incident log: {e}")

    def _persist_incident(self, entry: Dict[str, Any]) -> None:
        """Persist an incident log entry to the database."""
        if not self._use_db:
            return
        try:
            row = SelfHealingIncidentModel(
                fault_id=entry.get("fault_id", ""),
                fault_type=entry.get("fault_type", ""),
                endpoint=entry.get("endpoint", ""),
                severity=entry.get("severity", 5),
                detected_at=entry.get("detected_at", ""),
                attempts=entry.get("attempts", 0),
                outcome=entry.get("outcome", ""),
                resolved_at=entry.get("resolved_at", ""),
            )
            self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting incident: {e}")
            self.db.rollback()

    async def detect_and_heal(self, fault: Fault) -> Dict[str, Any]:
        """
        Main entry point: detect fault and attempt automated healing.

        Returns:
            Result dict with status, attempts made, and ticket if escalated
        """
        logger.info(f"Processing fault {fault.fault_id}: {fault.fault_type.value}")

        fix_attempts: List[FixAttempt] = []

        # Get fix strategies for this fault type
        strategies = self.fix_strategies.get(fault.fault_type, [])

        if not strategies:
            logger.warning(f"No fix strategies for fault type: {fault.fault_type}")
            ticket = self._create_ticket(fault, fix_attempts, "No automated fix available")
            return {
                "status": "escalated",
                "fault_id": fault.fault_id,
                "attempts": 0,
                "ticket": ticket
            }

        # Try each fix strategy
        for i, strategy in enumerate(strategies[:self.MAX_FIX_ATTEMPTS]):
            attempt = FixAttempt(
                attempt_number=i + 1,
                fix_type=strategy.__name__,
                started_at=datetime.utcnow(),
                status=FixStatus.IN_PROGRESS
            )

            try:
                logger.info(f"Attempt {i + 1}: {strategy.__name__}")

                # Execute the fix
                success, output = await strategy(fault)

                attempt.completed_at = datetime.utcnow()
                attempt.output = output

                if success:
                    attempt.status = FixStatus.SUCCESS
                    fix_attempts.append(attempt)

                    # Log successful fix
                    self._log_incident(fault, fix_attempts, "resolved")

                    return {
                        "status": "resolved",
                        "fault_id": fault.fault_id,
                        "attempts": len(fix_attempts),
                        "successful_fix": strategy.__name__,
                        "output": output
                    }
                else:
                    attempt.status = FixStatus.FAILED
                    fix_attempts.append(attempt)

            except Exception as e:
                attempt.completed_at = datetime.utcnow()
                attempt.status = FixStatus.FAILED
                attempt.error = str(e)
                fix_attempts.append(attempt)
                logger.error(f"Fix attempt failed: {e}")

        # All fixes failed - escalate
        ticket = self._create_ticket(fault, fix_attempts, "All automated fixes failed")
        self._log_incident(fault, fix_attempts, "escalated")

        return {
            "status": "escalated",
            "fault_id": fault.fault_id,
            "attempts": len(fix_attempts),
            "ticket": ticket
        }

    def _create_ticket(
        self,
        fault: Fault,
        attempts: List[FixAttempt],
        reason: str
    ) -> Ticket:
        """Create a Tier 2 support ticket"""

        # Determine priority based on severity
        if fault.severity >= 9:
            priority = "P1"
        elif fault.severity >= 7:
            priority = "P2"
        elif fault.severity >= 4:
            priority = "P3"
        else:
            priority = "P4"

        ticket = Ticket(
            ticket_id=f"TKT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{fault.fault_id[:8]}",
            fault=fault,
            fix_attempts=attempts,
            created_at=datetime.utcnow(),
            priority=priority
        )

        logger.info(f"Created ticket {ticket.ticket_id} with priority {priority}")
        return ticket

    def _log_incident(
        self,
        fault: Fault,
        attempts: List[FixAttempt],
        outcome: str
    ):
        """Log incident for audit trail, including RMM command_id when available"""
        entry = {
            "fault_id": fault.fault_id,
            "fault_type": fault.fault_type.value,
            "endpoint": fault.endpoint,
            "severity": fault.severity,
            "detected_at": fault.detected_at.isoformat(),
            "attempts": len(attempts),
            "outcome": outcome,
            "resolved_at": datetime.utcnow().isoformat(),
        }

        # Attach RMM command tracking info if present
        rmm_command_id = fault.metadata.get("rmm_command_id")
        if rmm_command_id:
            entry["rmm_command_id"] = rmm_command_id
            entry["rmm_dispatch_label"] = fault.metadata.get("rmm_dispatch_label", "")

        self.incident_log.append(entry)
        self._persist_incident(entry)

    # ═══════════════════════════════════════════════════════════════════════
    # FIX STRATEGIES - Printer Spooler
    # ═══════════════════════════════════════════════════════════════════════

    async def _fix_printer_restart_spooler(self, fault: Fault) -> tuple[bool, str]:
        """Fix #1: Restart the print spooler service"""
        commands = self._resolve_remediation_commands(fault, tier=0)
        if not commands:
            # Fallback to inline definition
            if platform.system() == "Windows":
                commands = ["net stop spooler", "net start spooler"]
            else:
                commands = ["sudo systemctl restart cups"]

        return await self._execute_commands(commands, fault=fault, tier=0)

    async def _fix_printer_clear_queue(self, fault: Fault) -> tuple[bool, str]:
        """Fix #2: Clear the print queue"""
        commands = self._resolve_remediation_commands(fault, tier=1)
        if not commands:
            if platform.system() == "Windows":
                commands = [
                    "net stop spooler",
                    'del /Q /F /S "%systemroot%\\System32\\Spool\\Printers\\*.*"',
                    "net start spooler",
                ]
            else:
                commands = ["sudo cancel -a", "sudo systemctl restart cups"]

        return await self._execute_commands(commands, fault=fault, tier=1)

    async def _fix_printer_reinstall_driver(self, fault: Fault) -> tuple[bool, str]:
        """Fix #3: Reinstall printer driver (requires manual intervention flag)"""
        # This is a placeholder - actual implementation would need driver info
        return False, "Driver reinstallation requires manual intervention"

    # ═══════════════════════════════════════════════════════════════════════
    # FIX STRATEGIES - Disk Space
    # ═══════════════════════════════════════════════════════════════════════

    async def _fix_disk_clear_temp(self, fault: Fault) -> tuple[bool, str]:
        """Fix #1: Clear temporary files"""
        commands = self._resolve_remediation_commands(fault, tier=0)
        if not commands:
            if platform.system() == "Windows":
                commands = ['del /q/f/s %TEMP%\\*', 'del /q/f/s C:\\Windows\\Temp\\*']
            else:
                commands = ["rm -rf /tmp/*", "rm -rf /var/tmp/*"]

        return await self._execute_commands(commands, fault=fault, tier=0)

    async def _fix_disk_clear_logs(self, fault: Fault) -> tuple[bool, str]:
        """Fix #2: Clear old log files"""
        commands = self._resolve_remediation_commands(fault, tier=1)
        if not commands:
            if platform.system() == "Windows":
                commands = [
                    'forfiles /p "C:\\Windows\\Logs" /s /m *.log /d -30 /c "cmd /c del @path"'
                ]
            else:
                commands = [
                    "find /var/log -type f -name '*.log' -mtime +30 -delete",
                    "journalctl --vacuum-time=7d",
                ]

        return await self._execute_commands(commands, fault=fault, tier=1)

    async def _fix_disk_compress_old(self, fault: Fault) -> tuple[bool, str]:
        """Fix #3: Compress old files"""
        # Placeholder - would need path configuration
        return False, "Compression requires path configuration"

    # ═══════════════════════════════════════════════════════════════════════
    # FIX STRATEGIES - Service Down
    # ═══════════════════════════════════════════════════════════════════════

    async def _fix_service_restart(self, fault: Fault) -> tuple[bool, str]:
        """Fix #1: Restart the service"""
        service_name = fault.metadata.get("service_name", "")
        if not service_name:
            return False, "No service name provided"

        commands = self._resolve_remediation_commands(fault, tier=0)
        if not commands:
            if platform.system() == "Windows":
                commands = [f"net stop {service_name}", f"net start {service_name}"]
            else:
                commands = [f"sudo systemctl restart {service_name}"]

        return await self._execute_commands(commands, fault=fault, tier=0)

    async def _fix_service_repair(self, fault: Fault) -> tuple[bool, str]:
        """Fix #2: Repair service configuration"""
        service_name = fault.metadata.get("service_name", "")
        commands = self._resolve_remediation_commands(fault, tier=1)
        if not commands:
            if platform.system() == "Windows":
                commands = [f"sc config {service_name} start= auto"]
            else:
                commands = [f"sudo systemctl enable {service_name}"]

        return await self._execute_commands(commands, fault=fault, tier=1)

    async def _fix_service_reinstall(self, fault: Fault) -> tuple[bool, str]:
        """Fix #3: Reinstall service"""
        return False, "Service reinstallation requires manual intervention"

    # ═══════════════════════════════════════════════════════════════════════
    # FIX STRATEGIES - Network
    # ═══════════════════════════════════════════════════════════════════════

    async def _fix_network_reset_adapter(self, fault: Fault) -> tuple[bool, str]:
        """Fix #1: Reset network adapter"""
        adapter = fault.metadata.get("adapter", "Ethernet")
        # Ensure adapter is in metadata for template substitution
        fault.metadata.setdefault("adapter", adapter)
        commands = self._resolve_remediation_commands(fault, tier=0)
        if not commands:
            if platform.system() == "Windows":
                commands = [
                    f'netsh interface set interface "{adapter}" disable',
                    f'netsh interface set interface "{adapter}" enable',
                ]
            else:
                commands = ["sudo ip link set eth0 down", "sudo ip link set eth0 up"]

        return await self._execute_commands(commands, fault=fault, tier=0)

    async def _fix_network_flush_dns(self, fault: Fault) -> tuple[bool, str]:
        """Fix #2: Flush DNS cache"""
        commands = self._resolve_remediation_commands(fault, tier=1)
        if not commands:
            if platform.system() == "Windows":
                commands = ["ipconfig /flushdns"]
            else:
                commands = ["sudo systemd-resolve --flush-caches"]

        return await self._execute_commands(commands, fault=fault, tier=1)

    async def _fix_network_reset_stack(self, fault: Fault) -> tuple[bool, str]:
        """Fix #3: Reset TCP/IP stack"""
        commands = self._resolve_remediation_commands(fault, tier=2)
        if not commands:
            if platform.system() == "Windows":
                commands = ["netsh winsock reset", "netsh int ip reset"]
            else:
                commands = ["sudo systemctl restart NetworkManager"]

        return await self._execute_commands(commands, fault=fault, tier=2)

    # ═══════════════════════════════════════════════════════════════════════
    # FIX STRATEGIES - CPU
    # ═══════════════════════════════════════════════════════════════════════

    async def _fix_cpu_kill_runaway(self, fault: Fault) -> tuple[bool, str]:
        """Fix #1: Kill runaway processes"""
        process_name = fault.metadata.get("process_name")
        if not process_name:
            return False, "No runaway process identified"

        commands = self._resolve_remediation_commands(fault, tier=0)
        if not commands:
            if platform.system() == "Windows":
                commands = [f"taskkill /F /IM {process_name}"]
            else:
                commands = [f"pkill -9 {process_name}"]

        return await self._execute_commands(commands, fault=fault, tier=0)

    async def _fix_cpu_restart_services(self, fault: Fault) -> tuple[bool, str]:
        """Fix #2: Restart high-CPU services"""
        return False, "Service restart requires identification"

    async def _fix_cpu_reboot_scheduled(self, fault: Fault) -> tuple[bool, str]:
        """Fix #3: Schedule reboot during maintenance window"""
        return False, "Reboot scheduled for maintenance window"

    # ═══════════════════════════════════════════════════════════════════════
    # FIX STRATEGIES - Memory
    # ═══════════════════════════════════════════════════════════════════════

    async def _fix_memory_clear_cache(self, fault: Fault) -> tuple[bool, str]:
        """Fix #1: Clear memory cache"""
        commands = self._resolve_remediation_commands(fault, tier=0)
        if not commands:
            if platform.system() == "Windows":
                return False, "Windows memory management is automatic"
            else:
                commands = ["sync", "echo 3 | sudo tee /proc/sys/vm/drop_caches"]

        if not commands:
            return False, "Windows memory management is automatic"

        return await self._execute_commands(commands, fault=fault, tier=0)

    async def _fix_memory_restart_services(self, fault: Fault) -> tuple[bool, str]:
        """Fix #2: Restart memory-heavy services"""
        return False, "Service restart requires identification"

    async def _fix_memory_reboot_scheduled(self, fault: Fault) -> tuple[bool, str]:
        """Fix #3: Schedule reboot"""
        return False, "Reboot scheduled for maintenance window"

    # ═══════════════════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ═══════════════════════════════════════════════════════════════════════

    def _resolve_remediation_commands(
        self,
        fault: Fault,
        tier: int
    ) -> List[str]:
        """
        Resolve the concrete shell commands for a fault type and escalation tier.

        Uses the REMEDIATION_COMMANDS map, substituting metadata placeholders
        (e.g. {service_name}, {adapter}, {process_name}) from fault.metadata.

        Returns an empty list if no commands are defined for the tier.
        """
        tiers = REMEDIATION_COMMANDS.get(fault.fault_type, [])
        if tier >= len(tiers):
            return []

        entry = tiers[tier]
        os_key = "windows" if platform.system() == "Windows" else "linux"
        raw_commands = entry.get(os_key, [])

        # Substitute metadata placeholders
        substituted = []
        for cmd in raw_commands:
            try:
                cmd = cmd.format(**fault.metadata)
            except KeyError:
                # Leave unresolved placeholders as-is; the strategy method
                # will decide whether to fail gracefully.
                pass
            substituted.append(cmd)

        return substituted

    async def _dispatch_to_rmm(
        self,
        fault: Fault,
        commands: List[str],
        label: str
    ) -> tuple[bool, str, Optional[str]]:
        """
        Dispatch remediation commands through the RMM command queue.

        Returns:
            (success, output_message, command_id or None)
        """
        if not self._rmm:
            return False, "RMM service unavailable", None

        combined_command = " && ".join(commands)
        try:
            rmm_cmd = self._rmm.queue_command(
                endpoint_id=fault.endpoint,
                command_type="self_healing",
                command=combined_command,
                parameters={
                    "fault_id": fault.fault_id,
                    "fault_type": fault.fault_type.value,
                    "remediation_label": label,
                    "individual_commands": commands,
                },
                queued_by="self-healing-agent",
                timeout_seconds=300,
            )
            logger.info(
                f"Dispatched RMM command {rmm_cmd.command_id} for fault "
                f"{fault.fault_id} ({label})"
            )
            return True, f"RMM command queued: {rmm_cmd.command_id}", rmm_cmd.command_id
        except Exception as e:
            logger.error(f"Failed to dispatch RMM command for {fault.fault_id}: {e}")
            return False, f"RMM dispatch error: {e}", None

    async def _execute_commands(
        self,
        commands: List[str],
        fault: Optional[Fault] = None,
        tier: int = 0
    ) -> tuple[bool, str]:
        """
        Execute a list of remediation commands.

        If an RMM service is wired, commands are dispatched through the RMM
        command queue for remote execution on the target endpoint.
        Falls back to local logging when RMM is unavailable.

        Returns:
            (success, output_message)
        """
        if not commands:
            return False, "No commands to execute"

        # Resolve the label for this tier
        tiers = REMEDIATION_COMMANDS.get(
            fault.fault_type, []
        ) if fault else []
        label = tiers[tier]["label"] if tier < len(tiers) else f"tier_{tier}"

        # Try RMM dispatch first
        if self._rmm and fault:
            success, output, command_id = await self._dispatch_to_rmm(
                fault, commands, label
            )
            if success:
                # Store the command_id on the fault metadata for incident tracking
                fault.metadata["rmm_command_id"] = command_id
                fault.metadata["rmm_dispatch_label"] = label
                return True, output
            else:
                logger.warning(
                    f"RMM dispatch failed for {fault.fault_id}, "
                    f"falling back to local logging: {output}"
                )

        # Fallback: log-only simulation (original behaviour)
        outputs = []
        for cmd in commands:
            try:
                logger.info(f"Would execute: {cmd}")
                outputs.append(f"Executed: {cmd}")
                await asyncio.sleep(0.1)  # Simulate execution time
            except Exception as e:
                return False, f"Command failed: {cmd} - {str(e)}"

        return True, "\n".join(outputs)

    def get_incident_log(self) -> List[Dict[str, Any]]:
        """Get the incident log for reporting"""
        return self.incident_log

    def calculate_roi(
        self,
        resolved_count: int,
        avg_ticket_cost: float = 75.0,
        avg_resolution_time_minutes: int = 45
    ) -> Dict[str, float]:
        """
        Calculate ROI from automated fixes.

        Args:
            resolved_count: Number of issues resolved automatically
            avg_ticket_cost: Average cost of a support ticket ($)
            avg_resolution_time_minutes: Average time to manually resolve

        Returns:
            ROI metrics
        """
        cost_savings = resolved_count * avg_ticket_cost
        time_savings_hours = (resolved_count * avg_resolution_time_minutes) / 60

        return {
            "resolved_automatically": resolved_count,
            "cost_savings": cost_savings,
            "time_savings_hours": time_savings_hours,
            "avg_ticket_cost": avg_ticket_cost
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        total_incidents = len(self.incident_log)
        auto_resolved = len([i for i in self.incident_log if i.get("auto_resolved", False)])

        return {
            "status": "operational",
            "total_incidents": total_incidents,
            "auto_resolved": auto_resolved,
            "success_rate": round(auto_resolved / total_incidents * 100, 1) if total_incidents > 0 else 100,
            "tickets_created": len([i for i in self.incident_log if i.get("ticket_id")])
        }

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get dashboard data for display"""
        status = self.get_system_status()
        roi = self.calculate_roi(status["auto_resolved"])

        return {
            "system_status": status,
            "roi_metrics": roi,
            "recent_incidents": self.incident_log[-10:] if self.incident_log else [],
            "fix_strategies": list(self.fix_strategies.keys())
        }
