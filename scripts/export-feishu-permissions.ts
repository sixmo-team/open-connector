import { writeFile } from "node:fs/promises";
import { feishuActions } from "../src/providers/feishu/actions.ts";

interface FeishuPermissionsExport {
  scopes: {
    tenant: string[];
    user: string[];
  };
}

const permissions: FeishuPermissionsExport = {
  scopes: {
    tenant: [],
    user: [...new Set(feishuActions.flatMap((action) => action.providerPermissions))].sort(),
  },
};

const contents = `${JSON.stringify(permissions, null, 2)}\n`;
const outputPath = process.argv[2];
if (outputPath) {
  await writeFile(outputPath, contents);
} else {
  process.stdout.write(contents);
}
