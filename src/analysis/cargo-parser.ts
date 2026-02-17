/**
 * Cargo.lock parser for extracting crate dependencies and versions
 */

export interface CargoLockDependency {
  name: string;
  version: string;
  source?: string;
  checksum?: string;
}

export interface CargoLock {
  version: number;
  dependencies: CargoLockDependency[];
}

/**
 * Parse Cargo.lock TOML file content
 */
export function parseCargoLock(content: string): CargoLock {
  const dependencies: CargoLockDependency[] = [];

  // Extract version from the file
  const versionMatch = content.match(/^version\s*=\s*(\d+)/m);
  const version = versionMatch ? parseInt(versionMatch[1], 10) : 3;

  // Parse [[package]] sections
  // Format:
  // [[package]]
  // name = "crate-name"
  // version = "1.0.0"
  // source = "registry+..."
  // checksum = "abc123..."

  const packagePattern =
    /\[\[package\]\]\s*\n((?:(?!^\[\[|\[package\]).*\n?)*)/gm;
  let match;

  while ((match = packagePattern.exec(content)) !== null) {
    const block = match[1];

    const nameMatch = block.match(/^name\s*=\s*"([^"]+)"/m);
    const versionMatch = block.match(/^version\s*=\s*"([^"]+)"/m);
    const sourceMatch = block.match(/^source\s*=\s*"([^"]+)"/m);
    const checksumMatch = block.match(/^checksum\s*=\s*"([^"]+)"/m);

    if (nameMatch && versionMatch) {
      dependencies.push({
        name: nameMatch[1],
        version: versionMatch[1],
        source: sourceMatch?.[1],
        checksum: checksumMatch?.[1],
      });
    }
  }

  return { version, dependencies };
}

/**
 * Parse Cargo.toml to extract direct dependencies
 */
export interface CargoTomlDependency {
  name: string;
  version?: string;
  path?: string;
  git?: string;
  features?: string[];
}

export interface CargoToml {
  name?: string;
  version?: string;
  dependencies: CargoTomlDependency[];
  devDependencies: CargoTomlDependency[];
}

/**
 * Parse Cargo.toml file content
 */
export function parseCargoToml(content: string): CargoToml {
  const dependencies: CargoTomlDependency[] = [];
  const devDependencies: CargoTomlDependency[] = [];

  // Extract package name and version
  const nameMatch = content.match(/^\[package\][^[]*name\s*=\s*"([^"]+)"/ms);
  const versionMatch = content.match(
    /^\[package\][^[]*version\s*=\s*"([^"]+)"/ms
  );

  // Parse [dependencies] section
  const depsMatch = content.match(
    /\[dependencies\]\s*\n((?:(?!\[(?!dependencies\.))[^\n]*\n?)*)/m
  );
  if (depsMatch) {
    parseDependencySection(depsMatch[1], dependencies);
  }

  // Parse [dev-dependencies] section
  const devDepsMatch = content.match(
    /\[dev-dependencies\]\s*\n((?:(?!\[(?!dev-dependencies\.))[^\n]*\n?)*)/m
  );
  if (devDepsMatch) {
    parseDependencySection(devDepsMatch[1], devDependencies);
  }

  return {
    name: nameMatch?.[1],
    version: versionMatch?.[1],
    dependencies,
    devDependencies,
  };
}

function parseDependencySection(
  section: string,
  deps: CargoTomlDependency[]
): void {
  // Simple dependency: crate = "1.0"
  const simplePattern = /^(\w[\w-]*)\s*=\s*"([^"]+)"/gm;
  let match;

  while ((match = simplePattern.exec(section)) !== null) {
    deps.push({
      name: match[1],
      version: match[2],
    });
  }

  // Complex dependency: crate = { version = "1.0", features = [...] }
  const complexPattern =
    /^(\w[\w-]*)\s*=\s*\{([^}]+)\}/gm;

  while ((match = complexPattern.exec(section)) !== null) {
    const name = match[1];
    const attrs = match[2];

    const versionMatch = attrs.match(/version\s*=\s*"([^"]+)"/);
    const pathMatch = attrs.match(/path\s*=\s*"([^"]+)"/);
    const gitMatch = attrs.match(/git\s*=\s*"([^"]+)"/);

    deps.push({
      name,
      version: versionMatch?.[1],
      path: pathMatch?.[1],
      git: gitMatch?.[1],
    });
  }
}

/**
 * Filter dependencies to only include registry-sourced crates
 * (excludes path and git dependencies which can't be vulnerability-checked)
 */
export function filterRegistryDeps(
  deps: CargoLockDependency[]
): CargoLockDependency[] {
  return deps.filter((dep) => {
    // Include if no source (defaults to registry) or explicitly from registry
    if (!dep.source) return true;
    return dep.source.startsWith('registry+');
  });
}
