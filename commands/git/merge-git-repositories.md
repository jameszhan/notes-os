# How to merge to git repostories

```bash
git remote add upstream git@github.com:jameszhan/hotchpotch_pythons.git
git pull
git checkout master
git merge --allow-unrelated-histories upstream/master
```

```bash
git lfs install --skip-smudge

git fetch git@github.com:jameszhan/hotchpotch_pythons.git master:hotchpotch_pythons
git checkout hotchpotch_pythons

git checkout master

git merge --allow-unrelated-histories hotchpotch_pythons
```

#### fatal: mll/data/train.csv：smudge 过滤器 lfs 失败 

```bash
// Skip smudge - We'll download binary files later in a faster batch
git lfs install --skip-smudge

// git fetch

// Fetch all the binary files in the new clone
git lfs pull

// Reinstate smudge
git lfs install --force
```

```bash
git clone git@github.com:jameszhan/hotchpotch_pythons.git
cd hotchpotch_pythons
git lfs pull

cd ../notes-ml
git remote add hotchpotch_pythons ../hotchpotch_pythons
git fetch hotchpotch_pythons
git rebase hotchpotch_pythons/master HEAD

git checkout -b tmp_branch
git checkout master
git merge tmp_branch

git remote remove hotchpotch_pythons
```


