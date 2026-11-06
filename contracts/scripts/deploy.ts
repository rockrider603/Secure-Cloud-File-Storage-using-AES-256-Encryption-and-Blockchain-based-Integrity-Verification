import { ethers } from 'hardhat';
async function main(){const registry=await (await ethers.getContractFactory('IntegrityRegistry')).deploy();await registry.waitForDeployment();console.log('IntegrityRegistry:',await registry.getAddress());}
main().catch(e=>{console.error(e);process.exitCode=1});
