---
-- IRC functions.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local stdnse = require "stdnse"
_ENV = stdnse.module("irc", stdnse.seeall)

--- Portrule for matching IRC services
--
-- @usage portrule = irc.portrule
--
-- @param host
-- @param port
-- @return Boolean true if the port is likely to be IRC
-- @class function
portrule = (require "shortport").port_or_service(
  {
    -- Shodan.io top 3 IRC Ports
    6667,
    6666,
    6664,
    -- other Ports in the "ircu" assignment block
    6665,
    6668,
    6669,
    -- common SSL irc Ports
    6679,
    6697,
    7000,
    -- other common Ports
    8067,
  },
  { "irc", "ircs", "ircs-u", "ircd", "irc-serv" } -- this covers Ports 194, 529, and 994
  )

return _ENV
