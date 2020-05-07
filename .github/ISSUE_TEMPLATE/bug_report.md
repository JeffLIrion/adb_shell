---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

### Description

<!--What is the bug and how to reproduce it-->

### Log

<!--A log from when the issue occurred-->

To enable debug logging in Python:

```python
import logging

logging.getLogger().setLevel(logging.DEBUG)
```

To enable debug logging in Home Assistant:

#### Approach 1: configuration.yaml

```yaml
logger:
  default: warning  # or whatever
    logs:
      aio_adb_shell: debug
```

#### Approach 2: `logger.set_level` service

```yaml
aio_adb_shell: debug
```
