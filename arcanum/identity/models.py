"""Data models for Active Directory & Identity Graph Analysis."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ADObject:
    """An Active Directory security principal (User, Group, Computer, GPO, OU)."""
    object_sid: str
    name: str
    object_type: str  # 'user', 'group', 'computer', 'gpo', 'ou'
    display_name: str = ""
    is_tier_zero: bool = False
    is_admin: bool = False
    has_spn: bool = False
    dont_req_preauth: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_sid": self.object_sid,
            "name": self.name,
            "object_type": self.object_type,
            "display_name": self.display_name or self.name,
            "is_tier_zero": self.is_tier_zero,
            "is_admin": self.is_admin,
            "has_spn": self.has_spn,
            "dont_req_preauth": self.dont_req_preauth,
            "metadata": self.metadata,
        }


@dataclass
class ADEdge:
    """A directed permission, membership or control edge between two AD objects."""
    source_sid: str
    target_sid: str
    relationship: str  # 'MemberOf', 'GenericAll', 'WriteDacl', 'WriteOwner', 'ForceChangePassword', 'DCSync', 'AdminTo', 'ExecuteDCOM', 'CertificateTemplateAbuse', 'AddMember'
    is_inherited: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_sid": self.source_sid,
            "target_sid": self.target_sid,
            "relationship": self.relationship,
            "is_inherited": self.is_inherited,
        }


@dataclass
class ADAttackPath:
    """An end-to-end exploit chain from a starting principal to a Tier-Zero target."""
    start_sid: str
    start_name: str
    target_sid: str
    target_name: str
    length: int
    hops: List[Dict[str, Any]]
    critical_exploit: Optional[str] = None
    narrative_ptbr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_sid": self.start_sid,
            "start_name": self.start_name,
            "target_sid": self.target_sid,
            "target_name": self.target_name,
            "length": self.length,
            "hops": self.hops,
            "critical_exploit": self.critical_exploit,
            "narrative_ptbr": self.narrative_ptbr,
        }


@dataclass
class KerberoastableUser:
    """A user account with a registered ServicePrincipalName prone to offline cracking."""
    sid: str
    name: str
    spn: str
    encryption_type: str = "RC4-HMAC"
    hash_sample: str = ""
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sid": self.sid,
            "name": self.name,
            "spn": self.spn,
            "encryption_type": self.encryption_type,
            "hash_sample": self.hash_sample,
            "mitigation": self.mitigation or "Utilizar Group Managed Service Accounts (gMSA) com senhas de 128 caracteres rotacionadas automaticamente ou aplicar criptografia AES256.",
        }


@dataclass
class ASREPRoastableUser:
    """A user account with DONT_REQ_PREAUTH bit set prone to pre-auth hash extraction."""
    sid: str
    name: str
    encryption_type: str = "RC4-HMAC"
    hash_sample: str = ""
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sid": self.sid,
            "name": self.name,
            "encryption_type": self.encryption_type,
            "hash_sample": self.hash_sample,
            "mitigation": self.mitigation or "Desmarcar a opção 'Do not require Kerberos preauthentication' na aba Conta do usuário no ADUC.",
        }


@dataclass
class ADChokePoint:
    """An identity node whose privilege severance neutralizes the highest volume of attack paths."""
    object_sid: str
    name: str
    object_type: str
    cut_paths_count: int
    cut_percentage: float
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_sid": self.object_sid,
            "name": self.name,
            "object_type": self.object_type,
            "cut_paths_count": self.cut_paths_count,
            "cut_percentage": round(self.cut_percentage, 1),
            "recommendation": self.recommendation,
        }
