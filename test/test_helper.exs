# The tshark tests decode messages with Wireshark's dissectors, and run where tshark is found:
# TSHARK, the PATH, or Wireshark's app on macOS.
tshark? =
  Enum.any?(
    [
      System.get_env("TSHARK"),
      System.find_executable("tshark"),
      "/Applications/Wireshark.app/Contents/MacOS/tshark"
    ],
    &(&1 != nil and File.exists?(&1))
  )

# The OpENer tests run against OpENer's sample application at OPENER, a host on another machine,
# the EIPScanner test runs the command EIPSCANNER against the adapter, and the corpus test reads
# the EDS files of the folder EDS_CORPUS.
exclude =
  if(tshark?, do: [], else: [:tshark]) ++
    if(System.get_env("OPENER"), do: [], else: [:opener]) ++
    if(System.get_env("EIPSCANNER"), do: [], else: [:eipscanner]) ++
    if(System.get_env("EDS_CORPUS"), do: [], else: [:eds_corpus])

ExUnit.start(exclude: exclude)
