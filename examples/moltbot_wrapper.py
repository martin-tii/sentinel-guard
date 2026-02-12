import warnings

from openclaw_wrapper import main


if __name__ == "__main__":
    warnings.warn(
        "examples/moltbot_wrapper.py is deprecated. Use examples/openclaw_wrapper.py instead.",
        DeprecationWarning,
        stacklevel=1,
    )
    main()
