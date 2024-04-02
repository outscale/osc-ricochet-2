

# Ideal integration Scenario:
## Rational:

Because clients can't use AK/SK to run CI, if client create a Pull Request, they can't run CI tests.

Of course, it would be ideal to treat clients and Outscale developers at the same level.

In order to achieve that, having Ricochet-2 been used as the only CI for Pull Request would be ideal. 

Because testing against TINA is still important, as ricochet-2 can contain bugs, We need to have tests running either on each merge on Default branch. Or a cron testing periodically the Default Branch.

It's important to remember that the Default Branch is a development branch, and can contain bugs, even if it's always better to catch bugs before patches are merged.
## Process:

- Pull Request CI, rely only on ricochet-2
- Default Branch CI rely on in-production tests.

# Side By Side integration
## Rational:

Of course, the ideal integration is harder to achieve, because we already have CI.

And moving tests from PR to Default Branch is something a little scary.

A way to push ricochet-2 smoothly in a project, is to create some small tests that use ricochet-2 and use them side-by-side with in-productions tests.

In practice, it's better to test resources that can be hard to tests due to quota limitations, such as DirectLinks or FlexibleGPUs.

## process:
- Create tests (see [here](https://github.com/outscale/osc-ricochet-2/blob/master/Road-To-Ricochet-2.md#technique-requirement)), and push CI tests at PR level.


# Technique Requirement:


- Create shell script that start/use ricochet
- set environements variables (as endpoints,ak.sk),
- run project tests.

Examples:

- https://github.com/outscale/pulumi-outscale/blob/master/local_tests.sh
- https://github.com/outscale/osc-cli/blob/master/local_tests.sh
- https://github.com/outscale/terraform-provider-outscale/blob/master/scripts/local-test.sh


Note that this shell script doesn't need to be at project root.

You could even push it in .github/scripts/, but I don't as I want local tests to be runnable locally.
