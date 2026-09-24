"""Utility modules for MLSecOps Agent v4.0."""

from . import config
from . import report_generator
from .cognitive_scratchpad import CognitiveScratchpad
from .tree_of_thought import TreeOfThoughtEngine, AttackVectorNode, VectorStatus, BacktrackEvent
from .cognitive_critic import CognitiveCritic, CriticVerdict
from .defense_evasion import DefenseEvasionEngine
from .secret_extractor import SecretExtractor, ExtractedIntelligence, calculate_shannon_entropy
from .exploit_chaining import ExploitChainingEngine
from .payload_mutator import PayloadMutator
from .cognitive_council import CognitiveCouncil, CouncilDeliberation
from .mcts_simulator import MCTSCyberSimulator, MCTSSimulationResult, MCTSNode
from .api_logic_fuzzer import APILogicFuzzer, APILogicFuzzTarget, APISchemaEndpoint
from .waf_fingerprinter import WAFFingerprinter, BlockedTokenAnalysis
from .patch_sandbox import PatchSynthesizer, PatchDiffResult, HotfixSandboxVerifier

__all__ = [
    "config",
    "report_generator",
    "CognitiveScratchpad",
    "TreeOfThoughtEngine",
    "AttackVectorNode",
    "VectorStatus",
    "BacktrackEvent",
    "CognitiveCritic",
    "CriticVerdict",
    "DefenseEvasionEngine",
    "SecretExtractor",
    "ExtractedIntelligence",
    "calculate_shannon_entropy",
    "ExploitChainingEngine",
    "PayloadMutator",
    "CognitiveCouncil",
    "CouncilDeliberation",
    "MCTSCyberSimulator",
    "MCTSSimulationResult",
    "MCTSNode",
    "APILogicFuzzer",
    "APILogicFuzzTarget",
    "APISchemaEndpoint",
    "WAFFingerprinter",
    "BlockedTokenAnalysis",
    "PatchSynthesizer",
    "PatchDiffResult",
    "HotfixSandboxVerifier",
]
