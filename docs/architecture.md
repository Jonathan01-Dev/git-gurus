# Architecture (Draft)

```text
+-------------+         multicast HELLO         +-------------+
| Node A      | <-----------------------------> | Node B      |
| UDP discover|                                 | UDP discover|
| TCP server  | <----- encrypted channels ----> | TCP server  |
+-------------+                                 +-------------+
        \                                           /
         \-------------+-------------+-------------/
                       | Node C      |
                       | peers/chunks|
                       +-------------+
```
