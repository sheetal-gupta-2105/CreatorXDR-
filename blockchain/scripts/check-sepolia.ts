
import { network } from "hardhat";

async function main() {
  const { ethers } = await network.connect();

  const [deployer] = await ethers.getSigners();

  const address = await deployer.getAddress();
  const balance = await ethers.provider.getBalance(address);
  const networkInfo = await ethers.provider.getNetwork();

  console.log("\n========== CREATORXDR SEPOLIA CHECK ==========");
  console.log("Wallet address:", address);
  console.log("ETH balance:", ethers.formatEther(balance));
  console.log("Chain ID:", networkInfo.chainId.toString());

  if (networkInfo.chainId !== 11155111n) {
    throw new Error("Wrong network! Expected Sepolia.");
  }

  if (balance === 0n) {
    console.log("WARNING: Wallet has no Sepolia ETH.");
  } else {
    console.log("Wallet is funded and ready.");
  }

  console.log("==============================================\n");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
