import axe from "axe-core";

/**
 * Runs axe-core on a rendered container and fails with a readable list of violations.
 * jsdom has no layout engine, so colour-contrast is excluded here: contrast is enforced separately
 * on the design tokens (src/design/contrast.test.ts). Everything structural (names, roles, labels,
 * landmarks, ARIA validity, heading order) is checked.
 */
export async function expectNoA11yViolations(container: Element): Promise<void> {
  const result = await axe.run(container, {
    rules: { "color-contrast": { enabled: false }, region: { enabled: false } },
  });
  const lines = result.violations.map((v) => `${v.id}: ${v.help}\n  ${v.nodes.map((n) => n.target.join(" ")).join("\n  ")}`);
  if (lines.length) throw new Error(`Accessibility violations:\n${lines.join("\n")}`);
}
