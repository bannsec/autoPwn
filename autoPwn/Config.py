# Container to hold global config

def get_proj_cfg():
    global cfg

    # Implicitly create cfg on-demand
    try:
        cfg
    except:
        cfg = proj.analyses.CFG()

    return cfg
