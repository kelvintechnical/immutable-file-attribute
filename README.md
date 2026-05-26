# Lab: Immutable File Attribute — `chattr +i` and `lsattr`

**Series:** linux-ops-mastery — RHCSA Permissions, Special Bits & ACLs
**Subjects covered:** ext2/3/4 file attributes via `e2fsprogs`, `chattr +i` (immutable), `chattr -i` removal, `lsattr` inspection, why root still cannot unlink until attribute cleared, loopback ext4 filesystem for predictable attribute support on RHEL 9 hosts rooted on XFS
**Career arcs covered:** RHCSA (protect critical files from accidental deletion), RHCE (documented manual hardening before automation), SRE ("stop the bleeding" during incidents), DevOps (WORM-like guardrails for CI secrets on ext4 data volumes), AI/MLOps (protect signed model manifests on ext4 caches)
**Prerequisite:** Lab 40 — comfortable as root in a disposable lab path
**Time Estimate:** 30 to 45 minutes
**Difficulty arc:** Task 1 loop ext4 sandbox · 2 baseline `lsattr` · 3 set immutable and prove writes fail · 4 prove root unlink fails · 5 contrast normal delete after `-i` · 6 capstone + cleanup

---

## Objective

Learn the **`immutable` (`+i`)** extended attribute available on common Linux local filesystems (classically ext family). A file marked `+i` cannot be modified, renamed, linked over, or deleted — **even by UID 0** — until the attribute is removed with `chattr -i`. By the end of this lab you can set, verify, and safely clear immutability on a throwaway ext4 loop mount.

The capstone is a defense-in-depth prompt: *"On your lab ext4 mount, make `/mnt/immut-lab/shadow-copy` immutable so neither users nor root can truncate it during rehearsal; then document removal steps."*

> **Lab safety note:** Practice only on the disposable loop mount under `/mnt/immut-lab`. **Never** experiment with `chattr +i` on production device nodes, bootloader paths, or RPM databases.

---

## Concept: Immutable Is a Filesystem-Level Circuit Breaker

POSIX permissions answer "who may write?" **File attributes** answer "has an administrator frozen this inode regardless of DAC?"

```
   Normal ext4 file
      rm / path allowed if DAC permits

   chattr +i file
      unlink / truncate / append blocked at VFS layer
             even if mode is 777 and you are root

   chattr -i file
      returns inode to normal policy evaluation
```

> **Why this matters:** Incident responders use `+i` to prevent attacker tampering on known-good binaries (after imaging) and to freeze evidence. Examiners want you to know the attribute exists and how to reverse it.

---

## 📜 Why File Attributes Exist — The Story

As ext2 matured, administrators wanted **orthogonal controls** beyond `chmod`: append-only logs, no-atime updates, and immutability for high-risk files. The `chattr` / `lsattr` interface exposed a parallel flag word stored alongside traditional inode metadata.

Capabilities, SELinux, and read-only bind mounts now overlap part of that design space — but `+i` remains popular because it is **one command**, works without policy modules, and is obvious in `lsattr` audits.

> **The point of the story:** Think of attributes as a second opinion the kernel consults after UID checks.

---

## 👪 The chattr Family — Who Lives There

| Attribute flag | `chattr` | Typical use |
|---|---|---|
| Immutable | `+i` / `-i` | Tamper resistance |
| Append-only | `+a` / `-a` | Logs — Lab 45 |
| No dump | `+d` | `dump` utility hint |
| Synchronous updates | `+S` | Rare performance/debug |

| Tool | Role |
|---|---|
| `lsattr` | List attributes (`----i---------e-----` style) |
| `chattr` | Modify attributes |
| `tune2fs -l` | ext4 feature overview of underlying FS |

> **The point of the family tree:** `+i` and `+a` are the two flags RHCSA-adjacent training most often emphasizes.

---

## 🔬 The Anatomy of `lsattr` Output — In One Diagram

```
$ lsattr /mnt/immut-lab/protected.conf
----i---------e----- /mnt/immut-lab/protected.conf
     │           └ ext4 extents attribute (common)
     └ immutable (i) present
```

> **Reading rule:** Letters appear in a fixed column map; focus on `i` and `a` positions for exams.

---

## 📚 Immutable Attribute Reference Table

| Task | Command | Notes |
|---|---|---|
| Set immutable | `chattr +i FILE` | Root operation |
| Clear immutable | `chattr -i FILE` | Required before delete |
| Show attributes | `lsattr FILE` | Recursive: `lsattr -R DIR` |
| Verify FS type | `findmnt /mnt/immut-lab` | Confirm ext4 for this lab |
| Create ext4 loop | `mkfs.ext4`, `mount` | Avoid XFS attribute gaps for teaching |

> **Rule one of immutability:** If `chattr -i` refuses, you may be on a read-only mount or different FS driver — diagnose with `findmnt`.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | Attribute questions appear in hardening objectives; know the verbs `+i` / `-i`. |
| **RHCE candidate** | Ansible cannot replace `chattr` semantics with `file` mode alone — sometimes shell out. |
| **SRE / Platform** | Break-glass: attackers rarely clear attributes if they do not know they exist — monitor `lsattr` drift. |
| **DevOps** | Protect golden config tarballs on ext4 data disks during migrations. |
| **AI / MLOps** | Freeze evaluation checksum files during audits. |

---

## 🔧 The 6 Tasks

> Six phases: **ext4 loop → inspect → apply +i → prove root blocked → remove `-i` → capstone**.

---

### Task 1 — Create an ext4 loop mount sandbox at `/mnt/immut-lab`

**Purpose:** RHEL 9 often uses XFS on `/`; ext4 loop guarantees `chattr +i` behaves as taught.

```bash
sudo -i
mkdir -p /root/immut-lab && cd /root/immut-lab

truncate -s 256M disk.img
LOOP=$(losetup -fP --show disk.img)
mkfs.ext4 -F -L immutlab "$LOOP"
mkdir -p /mnt/immut-lab
mount "$LOOP" /mnt/immut-lab
findmnt /mnt/immut-lab
```

**Human-Readable Breakdown:** Sparse file, loop device, ext4 format, mount under `/mnt/immut-lab`, verify.

**Reading it left to right:** `losetup -fP --show` attaches and prints `/dev/loopN`. `mkfs.ext4 -F` formats without interactive prompt.

**The story:** Attributes are filesystem-specific — isolating ext4 removes "why does my XFS host differ?" from the learning path.

**Expected output:**

```text
Writing superblocks and filesystem accounting information: done

TARGET        SOURCE     FSTYPE OPTIONS
/mnt/immut-lab /dev/loop1 ext4   rw,relatime
```

**Switches**

| Token | Meaning |
|---|---|
| `truncate -s 256M` | Backing sparse file |
| `mkfs.ext4 -F` | Force format non-interactively |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `losetup` fails | `modprobe loop`, check `losetup -a` for exhaustion |
| Mount wrong type | `blkid "$LOOP"` should say `TYPE="ext4"` |

---

### Task 2 — Baseline file and `lsattr` before mutation

**Purpose:** Create a normal file and capture default attribute string.

```bash
sudo -i
echo baseline > /mnt/immut-lab/readme.txt
lsattr /mnt/immut-lab/readme.txt
ls -l /mnt/immut-lab/readme.txt
```

**Human-Readable Breakdown:** Plain file should lack `i` until next task.

**Reading it left to right:** Default ext4 files often show only `e` (extents) among others depending on mkfs defaults.

**The story:** Baseline output is your diff anchor after `+i`.

**Expected output:**

```text
--------------e----- /mnt/immut-lab/readme.txt
-rw-r--r--. 1 root root 9 May 26 13:00 /mnt/immut-lab/readme.txt
```

**Switches**

| Token | Meaning |
|---|---|
| `lsattr FILE` | Single-file attribute listing |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `Operation not supported` | Not ext4 — repeat Task 1 on ext4 loop |
| File missing | Confirm mount still up: `findmnt /mnt/immut-lab` |

---

### Task 3 — Core operation: `chattr +i` and attempt user-level edits

**Purpose:** Flip immutable and show normal writes fail.

```bash
sudo -i
chattr +i /mnt/immut-lab/readme.txt
lsattr /mnt/immut-lab/readme.txt

bash -lc 'echo more >> /mnt/immut-lab/readme.txt' 2>&1 | head -n 1
```

**Human-Readable Breakdown:** Mark immutable, confirm `i` in `lsattr`, append as root still denied.

**Reading it left to right:** Immutability is evaluated before DAC — even root cannot write.

**The story:** This surprises everyone once — leverage the surprise for retention.

**Expected output:**

```text
----i---------e----- /mnt/immut-lab/readme.txt
bash: /mnt/immut-lab/readme.txt: Permission denied
```

**Switches**

| Token | Meaning |
|---|---|
| `chattr +i` | Add immutable flag |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Write still succeeds | Wrong attribute — re-run `lsattr` |
| `chattr: Operation not permitted while setting flags` | Underlying FS ignores flag — verify ext4 |

---

### Task 4 — Verification: root cannot delete until `-i`

**Purpose:** Prove unlink is blocked for superuser.

```bash
sudo -i
rm -f /mnt/immut-lab/readme.txt 2>&1 | head -n 1
chattr -i /mnt/immut-lab/readme.txt
lsattr /mnt/immut-lab/readme.txt
```

**Human-Readable Breakdown:** `rm` fails while `i` present; clearing attribute restores normal behavior (delete in Task 5).

**Reading it left to right:** Order matters — attempt delete first (fails), then `chattr -i`.

**The story:** Backup jobs that `rm -rf` a tree silently skip immutable files — attribute awareness prevents mystified on-call pages.

**Expected output:**

```text
rm: cannot remove '/mnt/immut-lab/readme.txt': Operation not permitted
--------------e----- /mnt/immut-lab/readme.txt
```

**Switches**

| Token | Meaning |
|---|---|
| `chattr -i` | Remove immutable flag |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Delete succeeded immediately | `+i` never applied — check `lsattr` |

---

### Task 5 — Edge case: rename and hardlink attempts also fail with `+i`

**Purpose:** Show immutability is broader than writes.

```bash
sudo -i
chattr +i /mnt/immut-lab/readme.txt

mv /mnt/immut-lab/readme.txt /mnt/immut-lab/renamed.txt 2>&1 | head -n 1

ln /mnt/immut-lab/readme.txt /mnt/immut-lab/hardlink 2>&1 | head -n 1

chattr -i /mnt/immut-lab/readme.txt
```

**Human-Readable Breakdown:** Expect `mv` and `ln` to fail while immutable; clear bit for capstone.

**Reading it left to right:** Immutable in ext4 historically blocks metadata changes affecting the inode.

**The story:** Attackers cannot `mv` away your file if you froze it — they must clear the flag first (auditable).

**Expected output:**

```text
mv: cannot move ... Operation not permitted
ln: failed to create hard link ... Operation not permitted
```

**Switches**

| Token | Meaning |
|---|---|
| `mv` | rename syscall exercise |
| `ln` | hard link attempt |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Different errno | Kernel version nuances — focus on failure not exact text |

---

### Task 6 — Capstone + cleanup

**Task statement:** *"Create `/mnt/immut-lab/shadow-copy` with realistic content, mark it `+i`, verify `lsattr`, attempt `truncate` and `rm` as root (both fail), then document the two-command unlock sequence and unmount the loop device."*

**Purpose:** Full incident-playbook rehearsal.

```bash
sudo -i
install -m 644 /dev/null /mnt/immut-lab/shadow-copy
echo "root:x:0:0:root:/root:/bin/bash" > /mnt/immut-lab/shadow-copy

chattr +i /mnt/immut-lab/shadow-copy
lsattr /mnt/immut-lab/shadow-copy

truncate -s 0 /mnt/immut-lab/shadow-copy 2>&1 | head -n 1
rm -f /mnt/immut-lab/shadow-copy 2>&1 | head -n 1

chattr -i /mnt/immut-lab/shadow-copy
rm -f /mnt/immut-lab/shadow-copy
```

**Cleanup**

```bash
sudo -i
umount /mnt/immut-lab || true
losetup -d "$LOOP" 2>/dev/null || losetup -a | grep immutlab
rm -rf /root/immut-lab /mnt/immut-lab
exit
```

**Expected output:**

```text
----i---------e----- /mnt/immut-lab/shadow-copy
truncate: cannot open ... Operation not permitted
rm: cannot remove ... Operation not permitted
```

**Switches**

| Token | Meaning |
|---|---|
| `truncate -s 0` | Attempt zero-length rewrite |
| `umount` | Teardown before `losetup -d` |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Busy mount | `lsof +D /mnt/immut-lab` |
| Loop not freed | `losetup -d /dev/loopN` from `losetup -a` |

---

## 🔍 Immutable Decision Guide

```
Need to freeze a file on ext4?
  │
  ├── "Even root must not delete during window"
  │       └── chattr +i file
  │
  ├── "Maintenance done — restore mutability"
  │       └── chattr -i file
  │
  ├── "Ansible keeps rewriting a file"
  │       └── template task fails until -i removed
  │
  └── "On XFS / btrfs attributes differ"
          └── consult FS-specific tools; use ext4 loop for RHCSA-style practice
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 Create ext4 loop mount at `/mnt/immut-lab`
- [ ] 02 Capture baseline `lsattr` on a normal file
- [ ] 03 Apply `+i` and prove append denied
- [ ] 04 Prove `rm` denied until `chattr -i`
- [ ] 05 Demonstrate `mv` / `ln` failures while immutable
- [ ] 06 Capstone `shadow-copy` drill and full teardown

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| `+i` on XFS lesson host | differs / unsupported | use ext4 loop from Task 1 |
| Forgot `-i` before maintenance | every change fails | `lsattr` first |
| Immutable directory surprises | cannot add files | rarely set `+i` on dirs without planning |
| RPM updates fail | immutable binaries | never `+i` system dirs casually |
| Loop not detached | disk.img busy | `umount` then `losetup -d` |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Memorize pair: `chattr +i` locks, `chattr -i` unlocks — always show `lsattr` proof in notes.

**RHCE candidate**
- Wrap `chattr` in `block:`/`rescue:` when hardening playbooks must be reversible.

**SRE / Platform interview**
- Contrast immutable files with read-only mounts — different blast radius and remount complexity.

**DevOps**
- Document attribute clearing in runbooks beside file permissions.

**AI / MLOps**
- Treat signed manifest blobs as WORM: `+i` after verification on ext4 artifact disks.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Lab 45 — Append-Only Attribute | `chattr +a` sibling flag |
| Lab 46 — Identifying File Attributes | `lsattr` deep patterns |
| Lab 40 — Standard File Permissions | DAC layer beneath attributes |
| Lab 02 — stderr redirection | Silence noisy loops while auditing |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)
