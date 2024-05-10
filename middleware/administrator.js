// administrator.js
const adminMiddleware = (req, res, next) => {
    // Check if user is logged in and is an administrator
    if (req.session && req.session.user && req.session.user.role === 'admin') {
        return next(); // User is logged in and is an administrator, proceed to the next middleware/route
    } else {
        return res.status(403).send('Forbidden'); // User is not logged in or not an administrator, send forbidden status
    }
};

module.exports = adminMiddleware;