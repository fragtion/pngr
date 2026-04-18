# pngr
pngr - A cross-platform, terminal-based Ping Grapher

Inspired by https://github.com/bp2008/pingtracer

## Usage
Takes a comma-separated list of hosts to ping. Each host can be customized with a set of arguments wrapped in curly-brackets as follows: {`ping-rate(pings/second)`, `y-axis low`, `y-axis high`, `ping high threshold`, `ping worse treshhold`}
- If a value is left blank, the script's default value is used
- Y-axis high/low resorts to automatic scaling if left blank

## Additional arguments:
`--braille` Use Unicode braille rendering for the graphs. Allows for higher resolution (twice as many horizontal points).

`--stretch` Stretch data to fill the full width before the buffer is full. Default is to scroll in from the right with the left side black.

`--rows x` Force the graph grid to use x many rows. Columns auto-adjust unless --cols is also supplied.

`--cols x` Force the graph grid to use x many columns. Rows auto-adjust unless --rows is also supplied.

`--payload-size x` ICMP payload size in bytes (0 = minimal, 8 embeds timestamp). Overrides default behavior.

`--timeout` Ping timeout in seconds for each probe before marking a packet as lost. This is separate from the send rate as set for each host.

`--debug` Enable debug output to stderr

Example:

`python3 pngr.py "1.1.1.1{5,0,10,5,7},129.151.169.143{5,0,25,21,23},196.10.99.18{0.1,0,100,80,90},69.180.123.1{5,0,300,200,230},10.13.1.22{5,165,300,180,190},10.1.7.1{3,0,300,180,220},10.77.1.1{3,165,300,220,250},10.77.2.1{3,165,300,220,250}" --rows 2`

<img width="982" height="514" alt="image" src="https://github.com/user-attachments/assets/f5551a4d-8228-4da1-b52f-4d3a4db5a561" />



`python3 pngr.py "1.1.1.1{5,0,10,5,7},129.151.169.143{5,0,25,21,23},196.10.99.18{0.1,0,100,80,90},69.180.123.1{5,0,300,200,230},10.13.1.22{5,165,300,180,190},10.1.7.1{3,0,300,180,220},10.77.1.1{3,165,300,220,250},10.77.2.1{3,165,300,220,250}" --rows 2 --braille`

<img width="992" height="512" alt="image" src="https://github.com/user-attachments/assets/68bef384-62c6-4bb8-9359-f10a520141cc" />

---

## License

MIT License. See `LICENSE` for details.

---

## Contributing

Pull requests, forks, issue and suggestion reports are all welcome.

## Coffee

Did this make you happy? I'd love to do more development like this! Please donate to show your support :)

**PayPal**: [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/donate/?business=2CGE77L7BZS3S&no_recurring=0)

**BTC:** 1Q4QkBn2Rx4hxFBgHEwRJXYHJjtfusnYfy

**XMR:** 4AfeGxGR4JqDxwVGWPTZHtX5QnQ3dTzwzMWLBFvysa6FTpTbz8Juqs25XuysVfowQoSYGdMESqnvrEQ969nR9Q7mEgpA5Zm
