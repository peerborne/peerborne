import { hasSafeIndexFieldPathSegments } from './field-path.js';

interface ProjectionBranch {
  fields: Record<string, unknown>;
  children?: Map<string, ProjectionBranch>;
}

/** Descend only through branches allocated for this projection. */
export class FieldProjection {
  #root: ProjectionBranch = { fields: {} };

  get fields(): Record<string, unknown> {
    return this.#root.fields;
  }

  set(path: string, value: unknown): void {
    const segments = path.split('.');
    if (!hasSafeIndexFieldPathSegments(segments)) {
      throw new TypeError('Invalid index projection path');
    }
    const name = segments.pop()!;
    let parent = this.#root;
    for (const segment of segments) {
      const children = (parent.children ??= new Map());
      let child = children.get(segment);
      if (child === undefined) {
        child = { fields: {} };
        defineOwnField(parent.fields, segment, child.fields);
        children.set(segment, child);
      }
      parent = child;
    }
    defineOwnField(parent.fields, name, value);
    parent.children?.delete(name);
  }
}

function defineOwnField(
  fields: Record<string, unknown>,
  name: string,
  value: unknown,
): void {
  Object.defineProperty(fields, name, {
    value,
    configurable: true,
    enumerable: true,
    writable: true,
  });
}
