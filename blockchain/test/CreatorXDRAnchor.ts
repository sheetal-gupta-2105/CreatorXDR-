
import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

describe("CreatorXDRAnchor", function () {
  async function deployFixture() {
    const [owner, attacker, anotherUser] =
      await ethers.getSigners();

    const anchor = await ethers.deployContract(
      "CreatorXDRAnchor"
    );

    return {
      anchor,
      owner,
      attacker,
      anotherUser,
    };
  }

  const ROOT_1 = ethers.keccak256(
    ethers.toUtf8Bytes("creatorxdr-audit-batch-001")
  );

  const ROOT_2 = ethers.keccak256(
    ethers.toUtf8Bytes("creatorxdr-audit-batch-002")
  );

  describe("Deployment", function () {
    it("Should assign the deployer as owner", async function () {
      const { anchor, owner } = await deployFixture();

      expect(await anchor.owner()).to.equal(owner.address);
    });
it("Should expose the correct contract version", async function () {
  const { anchor } = await deployFixture();

  expect(await anchor.CONTRACT_VERSION()).to.equal("1.0.0");
});

    it("Should initialize the total anchored roots to zero", async function () {
      const { anchor } = await deployFixture();

      expect(await anchor.totalAnchoredRoots()).to.equal(0n);
    });
  });

  describe("Root anchoring", function () {
    it("Should successfully anchor a valid Merkle root", async function () {
      const { anchor } = await deployFixture();

      await expect(anchor.anchorRoot(ROOT_1))
        .to.emit(anchor, "RootAnchored")
        .withArgs(
          ROOT_1,
          (await ethers.provider.getBlock("latest"))!.timestamp + 1,
          (await ethers.getSigners())[0].address
        );

      expect(await anchor.isAnchored(ROOT_1)).to.equal(true);
    });

    it("Should reject a zero Merkle root", async function () {
      const { anchor } = await deployFixture();

      const zeroRoot = ethers.ZeroHash;

      await expect(
        anchor.anchorRoot(zeroRoot)
      ).to.be.revertedWithCustomError(
        anchor,
        "InvalidMerkleRoot"
      );
    });

    it("Should reject duplicate Merkle roots", async function () {
      const { anchor } = await deployFixture();

      await anchor.anchorRoot(ROOT_1);

      await expect(
        anchor.anchorRoot(ROOT_1)
      ).to.be.revertedWithCustomError(
        anchor,
        "RootAlreadyAnchored"
      );
    });

    it("Should allow different Merkle roots", async function () {
      const { anchor } = await deployFixture();

      await anchor.anchorRoot(ROOT_1);
      await anchor.anchorRoot(ROOT_2);

      expect(await anchor.isAnchored(ROOT_1)).to.equal(true);
      expect(await anchor.isAnchored(ROOT_2)).to.equal(true);
      expect(await anchor.totalAnchoredRoots()).to.equal(2n);
    });
  });

  describe("Access control", function () {
    it("Should reject anchoring from non-owner wallets", async function () {
      const { anchor, attacker } = await deployFixture();

      await expect(
        anchor.connect(attacker).anchorRoot(ROOT_1)
      ).to.be.revertedWithCustomError(
        anchor,
        "Unauthorized"
      );
    });
  });

  describe("Anchor verification", function () {
    it("Should return the correct timestamp and submitter", async function () {
      const { anchor, owner } = await deployFixture();

      await anchor.anchorRoot(ROOT_1);

      const [timestamp, submitter] =
        await anchor.getAnchor(ROOT_1);

      expect(timestamp).to.be.greaterThan(0n);
      expect(submitter).to.equal(owner.address);
    });

    it("Should return zero values for an unknown root", async function () {
      const { anchor } = await deployFixture();

      const [timestamp, submitter] =
        await anchor.getAnchor(ROOT_1);

      expect(timestamp).to.equal(0n);
      expect(submitter).to.equal(ethers.ZeroAddress);
      expect(await anchor.isAnchored(ROOT_1)).to.equal(false);
    });
  });

  describe("Root count", function () {
    it("Should increment the count after each successful anchor", async function () {
      const { anchor } = await deployFixture();

      await anchor.anchorRoot(ROOT_1);
      expect(await anchor.totalAnchoredRoots()).to.equal(1n);

      await anchor.anchorRoot(ROOT_2);
      expect(await anchor.totalAnchoredRoots()).to.equal(2n);
    });
  });
describe("Ownership transfer", function () {
  it("Should allow the owner to initiate ownership transfer", async function () {
    const { anchor, owner, anotherUser } = await deployFixture();

    await expect(anchor.transferOwnership(anotherUser.address))
      .to.emit(anchor, "OwnershipTransferStarted")
      .withArgs(owner.address, anotherUser.address);

    expect(await anchor.pendingOwner()).to.equal(anotherUser.address);
    expect(await anchor.owner()).to.equal(owner.address);
  });

  it("Should transfer ownership after acceptance", async function () {
    const { anchor, anotherUser } = await deployFixture();

    await anchor.transferOwnership(anotherUser.address);
    await anchor.connect(anotherUser).acceptOwnership();

    expect(await anchor.owner()).to.equal(anotherUser.address);
    expect(await anchor.pendingOwner()).to.equal(ethers.ZeroAddress);
  });

  it("Should reject ownership acceptance from an unauthorized wallet", async function () {
    const { anchor, attacker } = await deployFixture();

    await expect(
      anchor.connect(attacker).acceptOwnership()
    ).to.be.revertedWithCustomError(anchor, "NotPendingOwner");
  });

  it("Should reject transfer to the zero address", async function () {
    const { anchor } = await deployFixture();

    await expect(
      anchor.transferOwnership(ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(anchor, "InvalidOwner");
  });
});
});
