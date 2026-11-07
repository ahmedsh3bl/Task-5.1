import { Router } from 'express';
import {
  loginInstructor,
  getDirectory,
  searchInstructors
} from '../controllers/instructorController.js';

const router = Router();

// The Instructor Portal has its own login (Joi-validated, bcrypt-verified);
// it does not use the student JWT requireAuth middleware.
router.post('/login', loginInstructor);
router.get('/', getDirectory);
router.get('/search', searchInstructors);

export default router;
