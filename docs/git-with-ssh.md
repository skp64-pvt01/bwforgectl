
# SSH Setup for use with multiple git repos

To manage multiple Git repositories using independent SSH keys, you must configure the **`~/.ssh/config` file** (not `~/.ssh/hosts`, which is not a standard OpenSSH file).

Here is the complete step-by-step process to generate unique keys, build your SSH configuration block, and match your Git repositories to the correct identity.

### 1. Generate Unique SSH Keys

Create distinct SSH key pairs for each account or repository. Provide a unique filename during the prompts so you do not overwrite your default keys:

```bash
# Key for your personal account
ssh-keygen -t ed25519 -C "personal@example.com" -f ~/.ssh/id_ed25519_personal

# Key for your work/organization account
ssh-keygen -t ed25519 -C "work@company.com" -f ~/.ssh/id_ed25519_work
```

*(Make sure to upload the respective public keys, like `~/.ssh/id_ed25519_work.pub`, to your GitHub or GitLab account profile settings).*

### 2. Configure Your `~/.ssh/config` File

Open or create your SSH configuration file:

```bash
nano ~/.ssh/config
```

Paste the following blocks, creating unique `Host` aliases to map specific SSH keys to the exact same provider destination (`github.com`):

```text
# Default / Personal Account Profile
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_personal
    IdentitiesOnly yes

# Work Account Profile
Host github.com-work
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_work
    IdentitiesOnly yes
```

* **`Host`**: The local shorthand nickname you will give Git.
* **`HostName`**: The real server address (e.g., `github.com` or `bitbucket.org`).
* **`IdentitiesOnly yes`**: Prevents SSH from trying other keys cached in your local SSH agent.

### 3. Match Git Repositories to Your Aliases

When routing your remote repository, modify the hostname to match your `Host` alias configuration.

#### Case A: Cloning a new repo

Instead of copying the raw SSH URL directly, substitute `github.com` with your work profile alias:

```bash
# Standard URL: git@github.com:company/project.git
# Modified Alias URL:
git clone git@github.com-work:company/project.git
```

#### Case B: Updating an existing repo

If you have already cloned the repository, navigate inside the directory and assign the new alias to your existing `origin` pointer:

```bash
git remote set-url origin git@github.com-work:company/project.git
```

### 4. Set Repository-Specific Git Author Details

Because you are using different SSH keys, you likely need different commit emails. Turn off global assumptions locally within your work workspace:

```bash
cd /path/to/work/repo
git config user.name "Your Work Name"
git config user.email "work@company.com"
```
