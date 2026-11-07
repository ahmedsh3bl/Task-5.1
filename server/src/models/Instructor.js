import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 10;

// Instructor Portal account.
//
// Security notes:
//  - `password` stores a bcrypt hash, never the plaintext. Hashing happens in
//    the pre('save') hook below, so every create()/save() path is covered.
//  - Secret fields are `select: false`, so they are NEVER returned by a query
//    unless the code explicitly opts in with `.select('+field')`. This is
//    defense in depth: even if a future endpoint forgets a projection, the
//    secrets stay out of the response.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true, select: false },
    department: { type: String, trim: true },
    role: { type: String, enum: ['instructor', 'superadmin'], default: 'instructor' },

    // Confidential — never exposed by the public directory or search.
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  { timestamps: true }
);

// Hash the password whenever it is set or changed.
// NOTE: Model.insertMany() does NOT run this hook — use create()/save().
instructorSchema.pre('save', async function hashPassword(next) {
  if (!this.isModified('password')) return next();
  try {
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
    return next();
  } catch (err) {
    return next(err);
  }
});

// Compare a plaintext candidate against the stored hash.
// The document must have been loaded with `.select('+password')`.
instructorSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
};

export const Instructor = mongoose.model('Instructor', instructorSchema);
