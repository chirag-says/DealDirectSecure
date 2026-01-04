/**
 * Role-Based Access Control (RBAC) Middleware
 * Enforces strict role checking - NO 'Agent' role allowed
 * 
 * Role Hierarchy:
 * - user (buyer): Can only access personal profile and saved properties
 * - owner: Can manage own properties and leads
 * - Admin/Manager roles are handled by authAdmin middleware
 */

// Valid roles in the system - Agent is PERMANENTLY RETIRED
const VALID_USER_ROLES = ['user', 'owner'];

/**
 * Middleware to ensure the 'Agent' role is never used
 * This acts as a safety net across the entire application
 */
export const blockRetiredRoles = (req, res, next) => {
    // Check request body for attempts to set retired roles
    if (req.body?.role && !VALID_USER_ROLES.includes(req.body.role)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid role specified',
            code: 'INVALID_ROLE'
        });
    }

    // Check if authenticated user somehow has a retired role
    if (req.user?.role && !VALID_USER_ROLES.includes(req.user.role)) {
        console.error(`⚠️ SECURITY: User ${req.user._id} has retired role: ${req.user.role}`);
        return res.status(403).json({
            success: false,
            message: 'Your account role is invalid. Please contact support.',
            code: 'RETIRED_ROLE'
        });
    }

    next();
};

/**
 * Require specific roles for route access
 * Usage: requireUserRole('owner') or requireUserRole('user', 'owner')
 */
export const requireUserRole = (...allowedRoles) => {
    // Validate that no retired roles are being allowed
    for (const role of allowedRoles) {
        if (!VALID_USER_ROLES.includes(role)) {
            throw new Error(`Invalid role in requireUserRole: ${role}`);
        }
    }

    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required',
                code: 'NOT_AUTHENTICATED'
            });
        }

        // Block any retired roles
        if (!VALID_USER_ROLES.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Invalid account role',
                code: 'INVALID_ROLE'
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to access this resource',
                code: 'INSUFFICIENT_ROLE'
            });
        }

        next();
    };
};

/**
 * Restrict buyers to only their own resources
 * Buyers can only:
 * - View/update their own profile
 * - View/manage their saved properties (interest list)
 * - Create saved searches
 */
export const buyerAccessOnly = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required',
            code: 'NOT_AUTHENTICATED'
        });
    }

    // Buyers (role: 'user') have limited access
    if (req.user.role === 'user') {
        // Allow access - specific resource checks happen in controllers
        return next();
    }

    // Owners have broader access
    if (req.user.role === 'owner') {
        return next();
    }

    return res.status(403).json({
        success: false,
        message: 'Access denied',
        code: 'ACCESS_DENIED'
    });
};

/**
 * Ensure user can only modify listings if they are Owner role
 * Buyers cannot create, update, or delete property listings
 */
export const ownerOnlyListingAccess = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required',
            code: 'NOT_AUTHENTICATED'
        });
    }

    if (req.user.role !== 'owner') {
        return res.status(403).json({
            success: false,
            message: 'Only property owners can perform this action',
            code: 'OWNER_ONLY'
        });
    }

    next();
};

/**
 * Log role-related security events
 */
export const logRoleAccess = (action) => {
    return (req, res, next) => {
        if (req.user) {
            console.log(`[RBAC] ${action} - User: ${req.user._id}, Role: ${req.user.role}, Path: ${req.path}`);
        }
        next();
    };
};

export { VALID_USER_ROLES };
