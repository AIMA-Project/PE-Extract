import lief


class LoadConfigDirectory (object):

    # Initializer
    def __init__ (self, load_cfg: lief.PE.LoadConfiguration = None):
        self.__security_cookie: lief.PE.LoadConfiguration = None
        # Setup class data
        self.setup (load_cfg)


    # Methods
    def setup (self, load_cfg: lief.PE.LoadConfiguration) -> None:
        if load_cfg is not None:
            pass

    def extract_sec_cookie (self, load_cfg: lief.PE.LoadConfiguration) -> None:
        self.security_cookie = load_cfg.security_cookie


    # Accessors and mutators
    @property
    def security_cookie (self) -> lief.PE.LoadConfiguration:
        return self.__security_cookie

    @security_cookie.setter
    def security_cookie (self, c: lief.PE.LoadConfiguration.security_cookie) -> None:
        self.__security_cookie = c
    

    # Overloads
    def __str__ (self) -> str:
        return ("Security Cookie: " + str (self.security_cookie)
               )



if __name__ == "__main__":
    lcd = LoadConfigDirectory ()
