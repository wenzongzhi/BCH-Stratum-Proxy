# BCH-Stratum-Proxy
A open source Bitcoin Cash Stratum Proxy.  
If a crypto enthusiast installs a full Bitcoin Cash node on Windows, they'll find it extremely difficult to find compatible software or programs to use the full node effectively, such as for mining or analyzing UTXO data. Therefore, this program aims to provide a tool for Windows Bitcoin full node users.

## user guide
This program runs on Windows 10/11.  
The PC running this program needs to have the BCHN full node software installed and RPC enabled.  
Modify the following parameters in the script,  
RPC_USER = "your_rpc_user"  
RPC_PASS = "your_rpc_password"  
RPC_HOST = "127.0.0.1"  
RPC_PORT = 8332  
At the same time, configure the block reward address in the script to your own Bitcoin Cash address (cash format),  
DEFAULT_PAYOUT_ADDRESS = "bitcoincash:your_default_address_here"  

## Communication process between ASIC miner, proxy and BCHN
```text
Miner                              Proxy                              BCH Node  
│                                   │                                   │  
│ --- TCP连接建立 ----------------   │                                   │  
│                                   │                                   │  
│ 发送 mining.subscribe              │                                   │  
│──────────────────────────────────>│                                   │  
│                                   │ 调用 getblocktemplate RPC         │  
│                                   │──────────────────────────────────>│  
│                                   │<──────────────────────────────────│  
│                                   │ 返回区块模板 (blocktemplate JSON) │  
│                                   │                                   │  
│<──────────────────────────────────│ 返回 result: extranonce1, size    │  
│ 收到订阅响应                        │                                   │  
│                                   │                                   │  
│ 发送 mining.authorize              │                                   │  
│──────────────────────────────────>│                                   │  
│                                   │ 检查 worker 名称／权限            │  
│                                   │                                   │  
│<──────────────────────────────────│ 返回 result:true（授权成功）      │  
│                                   │                                   │  
│                                   │ 从节点继续轮询 getblocktemplate   │  
│                                   │ 每隔 10~20秒刷新新区块模板           │  
│                                   │                                   │  
│<──────────────────────────────────│ mining.set_difficulty            │  
│<──────────────────────────────────│ mining.notify (新job下发)         │  
│                                   │                                   │  
│ 挖矿中：计算nonce + merkle root     │                                   │  
│                                   │                                   │  
│ 发送 mining.submit (share结果)     │                                   │  
│──────────────────────────────────>│                                   │  
│                                   │ 验证share有效性                     │  
│                                   │                                   │  
│                                   │ 若满足区块难度 → 提交给节点           │  
│                                   │──────────────────────────────────>│  
│                                   │<──────────────────────────────────│  
│                                   │ 节点接受区块（爆块成功）          │  
│                                   │                                   │  
│<──────────────────────────────────│ 返回结果: true / false            │  
│                                   │                                   │  
│                                   │ 循环等待下一轮 GBT 更新           │  
│                                   │                                   │  
```
