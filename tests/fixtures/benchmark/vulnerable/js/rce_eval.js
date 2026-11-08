// VULNERABLE: eval con entrada externa (RCE)
export function runComputation(userInput) {
  const result = eval(userInput);
  return result;
}
