/**
 * Analysis module index
 */

export {
  parseConfig,
  loadSourceConfigs,
  loadSinkConfigs,
  createTaintConfig,
  getDefaultConfig,
  DEFAULT_SOURCES,
  DEFAULT_SINKS,
  DEFAULT_SANITIZERS,
} from './config-loader.js';

export {
  analyzeTaint,
  isInDangerousPosition,
} from './taint-matcher.js';

export {
  detectUnresolved,
} from './unresolved.js';

export {
  generateFindings,
} from './findings.js';

export {
  propagateTaint,
  type TaintPropagationResult,
  type TaintedVariable,
  type TaintFlow,
} from './taint-propagation.js';

export {
  analyzeInterprocedural,
  getInterproceduralSummary,
  findTaintBridges,
  getMethodTaintPaths,
  hasMethod,
  getMethod,
  isMethodTainted,
  type InterproceduralResult,
  type MethodNode,
  type CallEdge,
} from './interprocedural.js';

export {
  analyzeConstantPropagation,
  isFalsePositive,
  isCorrelatedPredicateFP,
  ConstantPropagator,
  isKnown,
  createUnknown,
  createConstant,
  getNodeText,
  getNodeLine,
  type ConstantValue,
  type ConstantType,
  type ConstantPropagatorResult,
  type ConstantPropagationOptions,
} from './constant-propagation.js';

export {
  PathFinder,
  findTaintPaths,
  formatTaintPath,
  type TaintHop,
  type TaintPath,
  type PathFinderResult,
  type PathFinderConfig,
} from './path-finder.js';

export {
  DFGVerifier,
  verifyTaintFlow,
  formatVerificationResult,
  type VerificationResult,
  type VerificationPath,
  type VerificationStep,
  type VerifierConfig,
} from './dfg-verifier.js';

// RustSec Advisory Database
export {
  loadBundledAdvisories,
  parseAdvisoryJson,
  categoryToSeverity,
  getAdvisoriesForCrate,
  findAdvisoryByCve,
  getVulnerableCrates,
  type AdvisoryVulnerability,
  type AdvisoryDatabase,
} from './advisory-db.js';

export {
  parseCargoLock,
  parseCargoToml,
  filterRegistryDeps,
  type CargoLock,
  type CargoLockDependency,
  type CargoToml,
  type CargoTomlDependency,
} from './cargo-parser.js';

export {
  scanCargoLock,
  checkCrateVulnerability,
  formatFinding,
  formatScanReport,
  type DependencyFinding,
  type ScanOptions,
  type ScanResult,
} from './dependency-scanner.js';

export {
  parseVersion,
  compareVersions,
  semverSatisfies,
  isVersionVulnerable,
  type ParsedVersion,
} from './semver.js';
