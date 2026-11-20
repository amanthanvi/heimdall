The Windows full harness at 84d7c44e (PC job 11; bundle.json sha256 233131d862bceb1b0d2e38ef98a03fd9d7c9a997d7a090cc4806164a1daa94f9,
bundle.b64 sha256 d9ece5f9f4df83de24557b600670ab16c013c72fcc2be622f4805c5166059c04): exit 0, 111 binaries, 2895 passed, 0 failed,
34 ignored, canary 0. Superseded, kept on record: taskkill's stdout (`SUCCESS: The process with PID ... has been terminated.`)
landed inside libtest's result line of e2e_exit_m05 a02::a02_trusted_week_zero_further_prompts, which passed (it is in the
successes list) but could not be read as a result, so A02's Windows row read in_progress. Fixed by the test-only commit
85e67bfe; the records' Windows row is the run at 85e67bfe in ../windows/.
