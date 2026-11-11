/**
 * Who may do what. Three roles:
 *
 * - `user`: a station owner; their own stations and account only.
 * - `admin`: the admin dashboard, limited to the permissions the super admin gave them.
 * - `superadmin`: exactly one (the first account made); every permission, and the only
 *   one who changes roles and permissions or acts on another admin's account.
 */

export const PERMISSIONS = {
  "users.view": "See people",
  "users.manage": "Add, change, suspend and delete people (not admins)",
  "stations.view": "See every station",
  "stations.manage": "Create, rename, move, suspend and delete any station",
  "names.manage": "Reserve, block and release names",
  "plans.manage": "Create and change plans",
  "settings.manage": "Change the platform's settings and credentials",
  "logs.view": "See certificates, the audio relay, the audit log and DNS/ACME problems",
} as const;

export type Permission = keyof typeof PERMISSIONS;
export type Role = "user" | "admin" | "superadmin";
export const ALL_PERMISSIONS = Object.keys(PERMISSIONS) as Permission[];

export interface Principal {
  id: number;
  role: Role;
  permissions: string[];
}

export const isStaff = (u: Pick<Principal, "role"> | null | undefined) => !!u && (u.role === "admin" || u.role === "superadmin");
export const isSuper = (u: Pick<Principal, "role"> | null | undefined) => u?.role === "superadmin";

export function can(u: Principal | null | undefined, p: Permission): boolean {
  if (!u) return false;
  if (u.role === "superadmin") return true;
  return u.role === "admin" && u.permissions.includes(p);
}

/**
 * Whether `actor` may act on the account `target` (suspend, reset, delete, change plan).
 * Nobody acts on the super admin's account but the super admin, and only the super admin
 * acts on another admin's: an admin who could reset an admin's password could become them.
 */
export function mayActOn(actor: Principal, target: { id: number; role: Role }): boolean {
  if (actor.id === target.id) return false;
  if (target.role === "superadmin") return false;
  if (target.role === "admin") return actor.role === "superadmin";
  return can(actor, "users.manage");
}

/** Only known permission names, each once. */
export const cleanPermissions = (given: unknown[]): Permission[] =>
  [...new Set(given.map(String))].filter((p): p is Permission => p in PERMISSIONS);
