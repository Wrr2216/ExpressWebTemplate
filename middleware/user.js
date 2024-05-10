// user.js
const userMiddleware = (req, res, next) => {
    // Check if user is logged in
    if (req.session && req.session.user) {
        return next(); // User is logged in, proceed to the next middleware/route
    } else {
        return res.status(401).send('Unauthorized'); // User is not logged in, send unauthorized status
    }
};

module.exports = userMiddleware;
