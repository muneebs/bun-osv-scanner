export function startSpinner(message: string) {
  if (!process.stderr.isTTY)
    return { update: (_: string) => {}, stop: () => {} };

  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let i = 0;
  let current = message;

  process.stderr.write(`${frames[0]} ${current}`);
  const interval = setInterval(
    () => process.stderr.write(`\r${frames[++i % frames.length]} ${current}`),
    80
  );
  

  return {
    update(msg: string) {
      current = msg;
    },
    stop() {
      clearInterval(interval);
      process.stderr.write('\r\x1b[2K');
    },
  };
}
