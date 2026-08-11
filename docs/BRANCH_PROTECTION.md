# Branch protection / ruleset recommendation

Protect `main` before accepting outside contributions.

Recommended minimum:
- require a pull request before merge;
- require the Axven validation status check;
- block force pushes;
- block deletion of `main`;
- require the branch to be up to date before merging when practical;
- require CODEOWNERS review for consensus/security-sensitive paths once the
  project has more than one trusted reviewer.

For a solo-maintainer phase, requiring a second approval would prevent the
maintainer from merging their own work. Keep that disabled until another
trusted reviewer exists, while still requiring CI.

Do not grant workflow write permissions unless a workflow actually needs them.
