/**
 * RBAC Middleware
 * ---
 * Restricts route access based on user role.
 * Usage: authorize('admin', 'superadmin')
 */

/**
 * Returns middleware that only allows the specified roles.
 * @param  {...string} allowedRoles
 */
function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Role '${req.user.role}' does not have permission. Required: ${allowedRoles.join(', ')}`
      });
    }

    next();
  };
}

module.exports = { authorize };
