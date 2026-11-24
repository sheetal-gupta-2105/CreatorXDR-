
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("CreatorXDRAnchorModule", (m) => {
  const creatorXDRAnchor = m.contract("CreatorXDRAnchor");

  return { creatorXDRAnchor };
});
