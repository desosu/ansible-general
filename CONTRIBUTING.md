# Desarrollo

This repository uses [semantic versioning](https://semver.org/) for versioning. The version is defined in the `galaxy.yml` file. Update the `galaxy.yml` file with the current version and commit changes.

```bash
# Update the version in galaxy.yml
# Get the current version from the galaxy.yml file
# (galaxy.yml: version: 1.0.0)
version=$(grep '^version:' galaxy.yml | awk '{print $2}')

git add .
git commit -m "Update version to $version"

# Cambia a la rama main
git checkout main
git pull origin main
git merge --no-ff -m "feat: Update version in galaxy.yml to $version" develop

# Creates a new tag with the current version
git tag -a "v$version" -m "Version $version"
git push origin develop main --tags
git checkout develop
```
