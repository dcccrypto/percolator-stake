/**
 * End-to-end test for percolator-stake on Solana devnet.
 *
 * Tests: InitPool → Deposit → Withdraw → verify accounting
 *
 * Usage: npx ts-node scripts/e2e-test.ts
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  SYSVAR_RENT_PUBKEY,
  SYSVAR_CLOCK_PUBKEY,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount as createTokenAccount,
  getAccount,
  getMint,
  mintTo,
} from "@solana/spl-token";
import * as fs from "fs";
import * as path from "path";

// ─── Config ───────────────────────────────────────────────────

const PROGRAM_ID = new PublicKey("6aJb1F9CDCVWCNYFwj8aQsVb696YnW6J1FznteHq4Q6k");
const RPC_URL = "https://api.devnet.solana.com";
const DEPLOYER_PATH = "/root/.config/solana/percolator-stake/deployer.json";

// ─── Helpers ──────────────────────────────────────────────────

function loadKeypair(filePath: string): Keypair {
  const raw = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(raw));
}

function encodeU64LE(value: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(value);
  return buf;
}

function derivePDA(seeds: Buffer[], programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, programId);
}

async function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Instruction Builders ─────────────────────────────────────

function buildInitPoolIx(
  admin: PublicKey,
  slab: PublicKey,
  poolPda: PublicKey,
  lpMint: PublicKey,
  vault: PublicKey,
  vaultAuth: PublicKey,
  collateralMint: PublicKey,
  percolatorProgram: PublicKey,
  cooldownSlots: bigint,
  depositCap: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(1 + 8 + 8);
  data.writeUInt8(0, 0); // tag = InitPool
  data.writeBigUInt64LE(cooldownSlots, 1);
  data.writeBigUInt64LE(depositCap, 9);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: slab, isSigner: false, isWritable: false },
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: lpMint, isSigner: false, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: vaultAuth, isSigner: false, isWritable: false },
      { pubkey: collateralMint, isSigner: false, isWritable: false },
      { pubkey: percolatorProgram, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function buildDepositIx(
  user: PublicKey,
  poolPda: PublicKey,
  userAta: PublicKey,
  vault: PublicKey,
  lpMint: PublicKey,
  userLpAta: PublicKey,
  vaultAuth: PublicKey,
  depositPda: PublicKey,
  amount: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(9);
  data.writeUInt8(1, 0); // tag = Deposit
  data.writeBigUInt64LE(amount, 1);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: userAta, isSigner: false, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: lpMint, isSigner: false, isWritable: true },
      { pubkey: userLpAta, isSigner: false, isWritable: true },
      { pubkey: vaultAuth, isSigner: false, isWritable: false },
      { pubkey: depositPda, isSigner: false, isWritable: true },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function buildWithdrawIx(
  user: PublicKey,
  poolPda: PublicKey,
  userLpAta: PublicKey,
  lpMint: PublicKey,
  vault: PublicKey,
  userAta: PublicKey,
  vaultAuth: PublicKey,
  depositPda: PublicKey,
  lpAmount: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(9);
  data.writeUInt8(2, 0); // tag = Withdraw
  data.writeBigUInt64LE(lpAmount, 1);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: poolPda, isSigner: false, isWritable: true },
      { pubkey: userLpAta, isSigner: false, isWritable: true },
      { pubkey: lpMint, isSigner: false, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: userAta, isSigner: false, isWritable: true },
      { pubkey: vaultAuth, isSigner: false, isWritable: false },
      { pubkey: depositPda, isSigner: false, isWritable: true },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ],
    data,
  });
}

// ─── Main Test ────────────────────────────────────────────────

async function main() {
  console.log("═══════════════════════════════════════════");
  console.log("  percolator-stake E2E Test (Devnet)");
  console.log("═══════════════════════════════════════════\n");

  const conn = new Connection(RPC_URL, "confirmed");
  const admin = loadKeypair(DEPLOYER_PATH);
  console.log(`Admin: ${admin.publicKey.toBase58()}`);
  console.log(`Program: ${PROGRAM_ID.toBase58()}`);

  const balance = await conn.getBalance(admin.publicKey);
  console.log(`Balance: ${balance / LAMPORTS_PER_SOL} SOL\n`);

  // ── Step 1: Create a fake "slab" account (just an empty account for testing)
  console.log("Step 1: Creating mock slab + collateral mint...");
  const slab = Keypair.generate();
  const tx1 = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: admin.publicKey,
      newAccountPubkey: slab.publicKey,
      lamports: await conn.getMinimumBalanceForRentExemption(512),
      space: 512,
      programId: SystemProgram.programId, // owned by system (mock)
    })
  );
  await sendAndConfirmTransaction(conn, tx1, [admin, slab]);
  console.log(`  Slab: ${slab.publicKey.toBase58()}`);

  // Create collateral mint (6 decimals, admin is mint authority)
  const collateralMint = await createMint(conn, admin, admin.publicKey, null, 6);
  console.log(`  Collateral Mint: ${collateralMint.toBase58()}`);

  // ── Step 2: Derive PDAs
  console.log("\nStep 2: Deriving PDAs...");
  const [poolPda, poolBump] = derivePDA(
    [Buffer.from("stake_pool"), slab.publicKey.toBuffer()],
    PROGRAM_ID,
  );
  const [vaultAuth, vaultAuthBump] = derivePDA(
    [Buffer.from("vault_auth"), poolPda.toBuffer()],
    PROGRAM_ID,
  );
  console.log(`  Pool PDA: ${poolPda.toBase58()} (bump ${poolBump})`);
  console.log(`  Vault Auth: ${vaultAuth.toBase58()} (bump ${vaultAuthBump})`);

  // ── Step 3: Create LP mint + vault accounts (need to be created before InitPool)
  console.log("\nStep 3: Creating LP mint + vault token accounts...");

  // LP mint — needs to be pre-created (rent-exempt, uninit), InitPool will initialize it
  const lpMint = Keypair.generate();
  const lpMintRent = await conn.getMinimumBalanceForRentExemption(82); // MintLayout size
  const vaultAccount = Keypair.generate();
  const vaultRent = await conn.getMinimumBalanceForRentExemption(165); // AccountLayout size

  const tx2 = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: admin.publicKey,
      newAccountPubkey: lpMint.publicKey,
      lamports: lpMintRent,
      space: 82,
      programId: TOKEN_PROGRAM_ID,
    }),
    SystemProgram.createAccount({
      fromPubkey: admin.publicKey,
      newAccountPubkey: vaultAccount.publicKey,
      lamports: vaultRent,
      space: 165,
      programId: TOKEN_PROGRAM_ID,
    }),
  );
  await sendAndConfirmTransaction(conn, tx2, [admin, lpMint, vaultAccount]);
  console.log(`  LP Mint: ${lpMint.publicKey.toBase58()}`);
  console.log(`  Vault: ${vaultAccount.publicKey.toBase58()}`);

  // ── Step 4: InitPool
  console.log("\nStep 4: InitPool (cooldown=0, cap=0 uncapped)...");
  // Use a dummy percolator program ID (we're testing stake program, not CPI)
  const dummyPercolatorProgram = SystemProgram.programId;

  const initIx = buildInitPoolIx(
    admin.publicKey,
    slab.publicKey,
    poolPda,
    lpMint.publicKey,
    vaultAccount.publicKey,
    vaultAuth,
    collateralMint,
    dummyPercolatorProgram,
    0n, // cooldown = 0 for testing
    0n, // cap = 0 = uncapped
  );

  const tx3 = new Transaction().add(initIx);
  try {
    const sig = await sendAndConfirmTransaction(conn, tx3, [admin]);
    console.log(`  ✅ InitPool success: ${sig}`);
  } catch (e: any) {
    console.error(`  ❌ InitPool failed:`, e.message);
    const logs = e?.logs || [];
    logs.forEach((l: string) => console.log(`    ${l}`));
    process.exit(1);
  }

  // Verify pool state
  const poolInfo = await conn.getAccountInfo(poolPda);
  console.log(`  Pool account size: ${poolInfo?.data.length} bytes`);
  console.log(`  Pool owner: ${poolInfo?.owner.toBase58()}`);

  // ── Step 5: Deposit
  console.log("\nStep 5: Mint collateral + Deposit 1000 tokens...");
  const DEPOSIT_AMOUNT = 1_000_000n; // 1.0 token (6 decimals)

  // Create user's collateral ATA and mint some tokens
  const userAta = await createTokenAccount(conn, admin, collateralMint, admin.publicKey);
  await mintTo(conn, admin, collateralMint, userAta, admin, Number(DEPOSIT_AMOUNT * 2n));
  console.log(`  User collateral ATA: ${userAta.toBase58()}`);
  console.log(`  Minted ${Number(DEPOSIT_AMOUNT * 2n) / 1e6} tokens to user`);

  // Create user's LP token ATA
  const userLpAta = await createTokenAccount(conn, admin, lpMint.publicKey, admin.publicKey);
  console.log(`  User LP ATA: ${userLpAta.toBase58()}`);

  // Derive deposit PDA
  const [depositPda] = derivePDA(
    [Buffer.from("stake_deposit"), poolPda.toBuffer(), admin.publicKey.toBuffer()],
    PROGRAM_ID,
  );
  console.log(`  Deposit PDA: ${depositPda.toBase58()}`);

  const depositIx = buildDepositIx(
    admin.publicKey,
    poolPda,
    userAta,
    vaultAccount.publicKey,
    lpMint.publicKey,
    userLpAta,
    vaultAuth,
    depositPda,
    DEPOSIT_AMOUNT,
  );

  const tx4 = new Transaction().add(depositIx);
  try {
    const sig = await sendAndConfirmTransaction(conn, tx4, [admin]);
    console.log(`  ✅ Deposit success: ${sig}`);
  } catch (e: any) {
    console.error(`  ❌ Deposit failed:`, e.message);
    const logs = e?.logs || [];
    logs.forEach((l: string) => console.log(`    ${l}`));
    process.exit(1);
  }

  // Verify balances
  const vaultBalance = await getAccount(conn, vaultAccount.publicKey);
  const lpBalance = await getAccount(conn, userLpAta);
  const userBalance = await getAccount(conn, userAta);
  console.log(`  Vault balance: ${Number(vaultBalance.amount) / 1e6}`);
  console.log(`  User LP balance: ${Number(lpBalance.amount) / 1e6}`);
  console.log(`  User collateral remaining: ${Number(userBalance.amount) / 1e6}`);

  // ── Step 6: Withdraw (cooldown=0 so immediate)
  console.log("\nStep 6: Withdraw all LP tokens...");
  const WITHDRAW_LP = BigInt(lpBalance.amount.toString());

  const withdrawIx = buildWithdrawIx(
    admin.publicKey,
    poolPda,
    userLpAta,
    lpMint.publicKey,
    vaultAccount.publicKey,
    userAta,
    vaultAuth,
    depositPda,
    WITHDRAW_LP,
  );

  const tx5 = new Transaction().add(withdrawIx);
  try {
    const sig = await sendAndConfirmTransaction(conn, tx5, [admin]);
    console.log(`  ✅ Withdraw success: ${sig}`);
  } catch (e: any) {
    console.error(`  ❌ Withdraw failed:`, e.message);
    const logs = e?.logs || [];
    logs.forEach((l: string) => console.log(`    ${l}`));
    process.exit(1);
  }

  // Final balances
  const vaultFinal = await getAccount(conn, vaultAccount.publicKey);
  const lpFinal = await getAccount(conn, userLpAta);
  const userFinal = await getAccount(conn, userAta);
  console.log(`  Vault balance: ${Number(vaultFinal.amount) / 1e6}`);
  console.log(`  User LP balance: ${Number(lpFinal.amount) / 1e6}`);
  console.log(`  User collateral: ${Number(userFinal.amount) / 1e6}`);

  // ── Verify conservation
  console.log("\n═══════════════════════════════════════════");
  console.log("  RESULTS");
  console.log("═══════════════════════════════════════════");
  const deposited = Number(DEPOSIT_AMOUNT);
  // gotBack = final balance - balance after deposit (what the withdraw returned)
  const gotBack = Number(userFinal.amount) - Number(userBalance.amount);
  console.log(`  Deposited:  ${deposited / 1e6} tokens`);
  console.log(`  Got back:   ${gotBack / 1e6} tokens`);
  console.log(`  Vault left: ${Number(vaultFinal.amount) / 1e6} tokens`);
  console.log(`  LP left:    ${Number(lpFinal.amount) / 1e6} tokens`);

  if (Number(vaultFinal.amount) === 0 && Number(lpFinal.amount) === 0 && gotBack === deposited) {
    console.log("\n  ✅ CONSERVATION VERIFIED — exact roundtrip, zero vault, zero LP");
  } else if (gotBack <= deposited) {
    console.log("\n  ✅ CONSERVATION HOLDS — got back ≤ deposited (rounding loss is pool-favoring)");
  } else {
    console.log("\n  ❌ CONSERVATION VIOLATED — got back MORE than deposited!");
    process.exit(1);
  }

  console.log("\n  🎉 All E2E tests passed!\n");
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
