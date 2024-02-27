import express from "express";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import crypto from "crypto";
import { prisma } from "../../prisma";

const router = express.Router();

router.post("/password-reset-link", async (req, res) => {
  console.log("HIT ROUTE");
  const { email } = req.body;
  if (!email) {
    return res.status(400).send({ error: "Email is required." });
  }
  // todo: write your code here
  // 1. verify if email is in database

  const possibleUser = prisma.user.findFirst({
    where: {
      email: email,
    },
  });

  if (!possibleUser) {
    return res.status(400).send({ error: "Email not found." });
  }
  const token = crypto.randomBytes(20).toString("hex");

  const resetLink = process.env.FRONTEND_URL + `password-reset/${token}`;

  await prisma.user.update({
    where: { email: email },
    data: {
      resetToken: token,
      resetTokenExpiry: Date.now() + 3600000, // 1 hour from now
    },
  });
  //

  console.log("Sending email");
  // // Create a transporter object using the default SMTP transport
  const transporter = nodemailer.createTransport({
    service: "gmail", // Use your preferred email service
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.APP_PASSWORD,
    },
  });
  //
  // // Email content
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password Reset",
    text: `Click the link below to reset your password:\n\n${resetLink}\n\nIf you did not request a password reset, please ignore this email.`,
    // You'd typically generate a unique link for the user to reset their password
  };
  //
  try {
    await transporter.sendMail(mailOptions);
    res.status(200).send({ message: "Reset email sent successfully." });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).send({ error: "Failed to send reset email." });
  }

  return { message: "Reset email sent successfully." };
});

router.post("/password-reset/confirm", async (req, res) => {
  // 1. Find the user by the token
  // 2. Verify that the token hasn't expired
  // 3. Hash the new password
  // 4. Update the user's password in the database
  // 5. Invalidate the token so it can't be used again
  // 6. Send a response to the frontend
  const { token, password } = req.body;
  // console.log(token, password);

  // 1. Find the user by the token
  const possibleUser = await prisma.user.findFirst({
    where: {
      resetToken: token,
    },
  });

  if (!possibleUser) {
    return res.status(400).send({ error: "Token not found." });
  }

  // 2. Verify that the token hasn't expired (assuming you have an expiry date in your DB)
  if (
    !possibleUser.resetTokenExpiry ||
    possibleUser.resetTokenExpiry < Date.now()
  ) {
    return res.status(400).send({ error: "Token expired." });
  }

  // 3. Hash the new password
  const hashedPassword = await bcrypt.hash(password, 10);

  // 4. Update the user's password in the database
  await prisma.user.update({
    where: { id: possibleUser.id },
    data: {
      password: hashedPassword,
      resetToken: null,
      resetTokenExpiry: null,
    },
  });

  // 6. Send a response to the frontend
  return res.status(200).send({ message: "Password reset successfully." });
});

export default router;
