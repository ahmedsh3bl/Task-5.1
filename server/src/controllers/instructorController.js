import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  hardened against NoSQL injection
// =============================================================================
//
// Layers of defense (see Flow.md for the attacks each one stops):
//
//  1. express-mongo-sanitize (app.js) strips any key starting with `$` or
//     containing `.` from req.body / req.query / req.params, so operators such
//     as $ne, $gt, $regex and $where never reach Mongoose.
//  2. Joi validates the SHAPE and TYPE of every input here. username/password
//     must be plain strings and search accepts an allow-list of string fields.
//     Anything else is rejected (400) or stripped.
//  3. Passwords are bcrypt hashes; login looks the user up by username only and
//     verifies the password with bcrypt.compare, so the password never takes
//     part in a database query (no $regex oracle is possible).
//  4. Responses use explicit projections; secret fields (password, apiKey,
//     privateEmail, privatePhone) are never returned.
// =============================================================================

// Fields that are safe to show to anyone.
const PUBLIC_FIELDS = 'name department role';

// Profile returned to an instructor after a successful login. Confidential
// fields (apiKey, private contact info, password hash) are deliberately left
// out: the login response is stored client-side (localStorage) and must not
// carry secrets.
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// ---------------------------------------------------------------------------
// Validation schemas
// ---------------------------------------------------------------------------

const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(50).required(),
  password: Joi.string().min(1).max(128).required()
});

// Only these fields can be searched; unknown keys (e.g. `role`, `username`,
// `password`, `$where`) are stripped instead of being used as a filter.
const searchSchema = Joi.object({
  name: Joi.string().trim().max(100).allow(''),
  department: Joi.string().trim().max(50).allow('')
});

// Escape user text so it is matched literally inside a RegExp (prevents regex
// injection / ReDoS through the search box).
function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Pre-computed hash compared against when the username does not exist, so the
// response time does not reveal which usernames are valid.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    // Query by username ONLY (a validated string), never by password.
    const instructor = await Instructor.findOne({ username: value.username })
      .select('+password');

    const ok = await bcrypt.compare(
      value.password,
      instructor ? instructor.password : DUMMY_HASH
    );

    if (!instructor || !ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory with limited fields.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search?name=...&department=...
export async function searchInstructors(req, res, next) {
  try {
    const { value, error } = searchSchema.validate(req.query, { stripUnknown: true });
    if (error) return res.status(400).json({ message: error.message });

    // Build the filter ourselves from validated strings; the raw query object
    // is never handed to Mongoose.
    const filter = {};
    if (value.name) {
      filter.name = { $regex: escapeRegex(value.name), $options: 'i' };
    }
    if (value.department) {
      filter.department = { $regex: `^${escapeRegex(value.department)}$`, $options: 'i' };
    }

    const instructors = await Instructor.find(filter)
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .limit(50)
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
