import bcrypt from "bcrypt";

export async function createHash(password) {
  const hashPassword = await bcrypt.hash(password, bcrypt.genSaltSync(10));
  console.log("en el hash", password, hashPassword);
  

  return hashPassword;
}

export async function comparePassword(password, hashPassword) {
  const isPasswordCorrect = await bcrypt.compare(password, hashPassword);

  console.log("compara", password, isPasswordCorrect);
  

  return isPasswordCorrect;
}
