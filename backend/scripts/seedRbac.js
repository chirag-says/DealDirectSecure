/**
 * RBAC Seed Script
 * Initializes default roles and permissions for the admin system
 * 
 * ROLES HIERARCHY (Agent role is NOT supported):
 * - Super Admin (Level 100): Full access
 * - Administrator (Level 80): Most features
 * - Manager (Level 50): Properties, leads, reports
 * - Viewer (Level 10): Read-only access
 * 
 * Usage: node scripts/seedRbac.js
 */
import dotenv from "dotenv";
dotenv.config();

import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import Role from "../models/Role.js";
import Permission from "../models/Permission.js";
import Admin from "../models/Admin.js";

const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/dealdirect";

/**
 * Default permissions for the system
 */
const defaultPermissions = [
    // Dashboard
    { resource: "dashboard", action: "read", name: "View Dashboard", description: "Access dashboard statistics and analytics" },

    // Users
    { resource: "users", action: "read", name: "View Users", description: "View user list and details" },
    { resource: "users", action: "create", name: "Create Users", description: "Create new user accounts" },
    { resource: "users", action: "update", name: "Edit Users", description: "Modify user information" },
    { resource: "users", action: "delete", name: "Delete Users", description: "Remove user accounts" },
    { resource: "users", action: "manage", name: "Manage Users", description: "Full user management access" },

    // Admins
    { resource: "admins", action: "read", name: "View Admins", description: "View admin list and details" },
    { resource: "admins", action: "create", name: "Create Admins", description: "Create new admin accounts" },
    { resource: "admins", action: "update", name: "Edit Admins", description: "Modify admin information" },
    { resource: "admins", action: "delete", name: "Delete Admins", description: "Remove admin accounts" },
    { resource: "admins", action: "manage", name: "Manage Admins", description: "Full admin management access" },

    // Properties
    { resource: "properties", action: "read", name: "View Properties", description: "View property listings" },
    { resource: "properties", action: "create", name: "Create Properties", description: "Add new properties" },
    { resource: "properties", action: "update", name: "Edit Properties", description: "Modify property details" },
    { resource: "properties", action: "delete", name: "Delete Properties", description: "Remove properties" },
    { resource: "properties", action: "approve", name: "Approve Properties", description: "Approve property listings" },
    { resource: "properties", action: "reject", name: "Reject Properties", description: "Reject property listings" },
    { resource: "properties", action: "manage", name: "Manage Properties", description: "Full property management access" },

    // Leads
    { resource: "leads", action: "read", name: "View Leads", description: "View lead information" },
    { resource: "leads", action: "create", name: "Create Leads", description: "Create new leads" },
    { resource: "leads", action: "update", name: "Edit Leads", description: "Update lead status and details" },
    { resource: "leads", action: "delete", name: "Delete Leads", description: "Remove leads" },
    { resource: "leads", action: "export", name: "Export Leads", description: "Export lead data" },
    { resource: "leads", action: "manage", name: "Manage Leads", description: "Full lead management access" },

    // Reports
    { resource: "reports", action: "read", name: "View Reports", description: "View reported content" },
    { resource: "reports", action: "update", name: "Handle Reports", description: "Update report status" },
    { resource: "reports", action: "manage", name: "Manage Reports", description: "Full report management access" },

    // Categories
    { resource: "categories", action: "read", name: "View Categories", description: "View property categories" },
    { resource: "categories", action: "create", name: "Create Categories", description: "Add new categories" },
    { resource: "categories", action: "update", name: "Edit Categories", description: "Modify categories" },
    { resource: "categories", action: "delete", name: "Delete Categories", description: "Remove categories" },
    { resource: "categories", action: "manage", name: "Manage Categories", description: "Full category management access" },

    // Settings
    { resource: "settings", action: "read", name: "View Settings", description: "View system settings" },
    { resource: "settings", action: "update", name: "Edit Settings", description: "Modify system settings" },
    { resource: "settings", action: "manage", name: "Manage Settings", description: "Full settings management access" },

    // Audit Logs
    { resource: "audit_logs", action: "read", name: "View Audit Logs", description: "Access audit trail" },
    { resource: "audit_logs", action: "export", name: "Export Audit Logs", description: "Export audit data" },

    // Analytics
    { resource: "analytics", action: "read", name: "View Analytics", description: "Access analytics and insights" },
    { resource: "analytics", action: "export", name: "Export Analytics", description: "Export analytics data" },

    // Messages
    { resource: "messages", action: "read", name: "View Messages", description: "View chat messages" },
    { resource: "messages", action: "delete", name: "Delete Messages", description: "Remove messages" },
    { resource: "messages", action: "manage", name: "Manage Messages", description: "Full message management access" },

    // Notifications
    { resource: "notifications", action: "read", name: "View Notifications", description: "View notifications" },
    { resource: "notifications", action: "create", name: "Send Notifications", description: "Send system notifications" },
    { resource: "notifications", action: "manage", name: "Manage Notifications", description: "Full notification management access" },
];

/**
 * Default roles with their permission assignments
 * NOTE: Only 4 roles are supported - NO AGENT ROLE
 */
const defaultRoles = [
    {
        name: "super_admin",
        displayName: "Super Administrator",
        description: "Full system access with all privileges. Can manage other admins and access audit logs.",
        level: 100,
        canManageAdmins: true,
        isSystem: true,
        permissions: "*", // All permissions
    },
    {
        name: "admin",
        displayName: "Administrator",
        description: "Administrative access to most features except admin management and audit logs.",
        level: 80,
        canManageAdmins: false,
        isSystem: true,
        permissions: [
            "dashboard:read",
            "users:read", "users:update", "users:manage",
            "properties:read", "properties:create", "properties:update", "properties:approve", "properties:reject", "properties:manage",
            "leads:read", "leads:update", "leads:export", "leads:manage",
            "reports:read", "reports:update", "reports:manage",
            "categories:read", "categories:create", "categories:update", "categories:delete", "categories:manage",
            "analytics:read", "analytics:export",
            "messages:read", "messages:delete", "messages:manage",
            "notifications:read", "notifications:create", "notifications:manage",
        ],
    },
    {
        name: "manager",
        displayName: "Manager",
        description: "Management access to properties, leads, and reports. Cannot modify users or system settings.",
        level: 50,
        canManageAdmins: false,
        isSystem: true,
        permissions: [
            "dashboard:read",
            "users:read",
            "properties:read", "properties:create", "properties:update", "properties:approve", "properties:reject",
            "leads:read", "leads:update",
            "reports:read", "reports:update",
            "categories:read",
            "analytics:read",
            "messages:read",
            "notifications:read",
        ],
    },
    {
        name: "viewer",
        displayName: "Viewer",
        description: "Read-only access to dashboard, properties, leads, and categories.",
        level: 10,
        canManageAdmins: false,
        isSystem: true,
        permissions: [
            "dashboard:read",
            "properties:read",
            "leads:read",
            "categories:read",
            "notifications:read",
        ],
    },
];

async function seedDatabase() {
    try {
        console.log("🔌 Connecting to MongoDB...");
        await mongoose.connect(MONGODB_URI);
        console.log("✅ Connected to MongoDB\n");

        // Step 0: Remove any existing 'agent' role (cleanup from previous versions)
        console.log("🧹 Cleaning up deprecated roles...");
        const deletedAgentRole = await Role.deleteOne({ name: "agent" });
        if (deletedAgentRole.deletedCount > 0) {
            console.log("  ✓ Removed deprecated 'agent' role");
        } else {
            console.log("  ✓ No deprecated roles found");
        }
        console.log("");

        // Step 1: Create permissions
        console.log("📝 Creating permissions...");
        const permissionMap = new Map();

        for (const perm of defaultPermissions) {
            const code = `${perm.resource}:${perm.action}`;
            const permission = await Permission.findOneAndUpdate(
                { code },
                { ...perm, code, isSystem: true, isActive: true },
                { upsert: true, new: true }
            );
            permissionMap.set(code, permission._id);
            console.log(`  ✓ ${code}`);
        }
        console.log(`\n✅ Created ${permissionMap.size} permissions\n`);

        // Step 2: Create roles with permissions
        console.log("👥 Creating roles...");
        const roleMap = new Map();

        for (const roleData of defaultRoles) {
            let permissionIds = [];

            if (roleData.permissions === "*") {
                // Super admin gets all permissions
                permissionIds = Array.from(permissionMap.values());
            } else {
                // Map permission codes to IDs
                permissionIds = roleData.permissions
                    .map(code => permissionMap.get(code))
                    .filter(id => id);
            }

            const { permissions, ...roleFields } = roleData;

            const role = await Role.findOneAndUpdate(
                { name: roleData.name },
                { ...roleFields, permissions: permissionIds, isActive: true },
                { upsert: true, new: true }
            );

            roleMap.set(roleData.name, role._id);
            console.log(`  ✓ ${roleData.displayName} (Level ${roleData.level}) - ${permissionIds.length} permissions`);
        }
        console.log(`\n✅ Created ${roleMap.size} roles\n`);

        // Step 3: Migrate any admins with deprecated 'agent' role to 'viewer'
        console.log("🔄 Checking for admins with deprecated roles...");
        const deprecatedRoleId = await Role.findOne({ name: "agent" });
        if (deprecatedRoleId) {
            const migratedCount = await Admin.updateMany(
                { role: deprecatedRoleId._id },
                { role: roleMap.get("viewer") }
            );
            if (migratedCount.modifiedCount > 0) {
                console.log(`  ✓ Migrated ${migratedCount.modifiedCount} admins from 'agent' to 'viewer' role`);
            }
        }
        console.log("");

        // Step 4: Check if super admin exists, create if not
        console.log("🔐 Checking for super admin...");
        const existingSuperAdmin = await Admin.findOne({
            role: roleMap.get("super_admin"),
        });

        if (!existingSuperAdmin) {
            // Create default super admin
            const defaultEmail = process.env.SUPER_ADMIN_EMAIL || "superadmin@dealdirect.com";
            const defaultPassword = process.env.SUPER_ADMIN_PASSWORD || "SuperAdmin@123!";

            // Check if any admin with this email exists
            const existingAdmin = await Admin.findOne({ email: defaultEmail });

            if (!existingAdmin) {
                const hashedPassword = await bcrypt.hash(defaultPassword, 12);

                await Admin.create({
                    name: "Super Administrator",
                    email: defaultEmail,
                    password: hashedPassword,
                    role: roleMap.get("super_admin"),
                    isActive: true,
                    mfa: {
                        enabled: false,
                        required: true, // Will be prompted to setup MFA on first login
                    },
                    security: {
                        mustChangePassword: true, // Must change password on first login
                    },
                });

                console.log(`  ✓ Created super admin account`);
                console.log(`    Email: ${defaultEmail}`);
                console.log(`    Password: ${defaultPassword}`);
                console.log(`    ⚠️  IMPORTANT: Change this password immediately on first login!\n`);
            } else {
                // Update existing admin to super admin role
                existingAdmin.role = roleMap.get("super_admin");
                await existingAdmin.save();
                console.log(`  ✓ Updated existing admin "${existingAdmin.email}" to super admin role\n`);
            }
        } else {
            console.log(`  ✓ Super admin already exists: ${existingSuperAdmin.email}\n`);
        }

        console.log("====================================");
        console.log("🎉 RBAC seed completed successfully!");
        console.log("====================================\n");

        console.log("📋 Summary:");
        console.log(`   • ${permissionMap.size} permissions created`);
        console.log(`   • ${roleMap.size} roles created (Super Admin, Administrator, Manager, Viewer)`);
        console.log(`   • Super admin account ready`);
        console.log("\n🔒 Security notes:");
        console.log("   1. Change the default super admin password immediately");
        console.log("   2. Setup MFA on the super admin account");
        console.log("   3. Configure SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD in .env for production");
        console.log("   4. The 'Agent' role has been REMOVED from the system\n");

    } catch (error) {
        console.error("❌ Seed error:", error);
        process.exit(1);
    } finally {
        await mongoose.connection.close();
        console.log("🔌 Database connection closed");
    }
}

// Run the seed
seedDatabase();
