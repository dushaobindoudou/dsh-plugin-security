/**
 * Register the bundled review skill (skills/dsh-plugin-security/SKILL.md)
 * with the host skill registry, so agents can load it right after the plugin
 * is installed — no manual link into `$DSH_HOME/skills`.
 *
 * @module dsh-plugin-security/skill
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const SKILL_PATH = fileURLToPath(new URL('../skills/dsh-plugin-security/SKILL.md', import.meta.url));

/** Split a SKILL.md into its frontmatter `name` / `description` and body. */
export function parseSkill(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (match === null) throw new Error('SKILL.md has no frontmatter');
  const field = (key) => {
    const line = match[1].split(/\r?\n/).find((l) => l.startsWith(`${key}:`));
    return line === undefined ? undefined : line.slice(key.length + 1).trim().replace(/^(['"])(.*)\1$/, '$2');
  };
  const name = field('name');
  const description = field('description');
  if (!name || !description) throw new Error('SKILL.md frontmatter needs name and description');
  return { name, description, content: match[2].trim() };
}

/**
 * @param {object} skills the host `ctx.skills` registry
 * @returns the registry disposer, or null when the registry is unusable
 */
export function registerBundledSkill(skills, path = SKILL_PATH) {
  if (skills === undefined || skills === null || typeof skills.register !== 'function') return null;
  const skill = parseSkill(readFileSync(path, 'utf8'));
  return skills.register({ ...skill, source: 'runtime', path });
}
