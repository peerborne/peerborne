import React from "react";
import { createEditor, Descendant } from 'slate';
import {
  Slate,
  Editable,
  withReact,
  type RenderElementProps,
  type RenderLeafProps,
} from 'slate-react';
import { withHistory } from 'slate-history';
import { Element, Leaf, onHotkeyDown, Toolbar } from './Slate';

export function SlateInput({placeholder, disabled, value, onChange}: {
    placeholder?: string;
    disabled?: boolean;
    value: Descendant[];
    onChange: (description: Descendant[]) => void;
}) {
    const editor = React.useMemo(() => withHistory(withReact(createEditor())), []);
    const renderElement = React.useCallback((props: RenderElementProps) => <Element {...props} />, []);
    const renderLeaf = React.useCallback((props: RenderLeafProps) => <Leaf {...props} />, []);

    return (
        <Slate
            editor={editor}
            initialValue={value}
            onChange={onChange}
        >
            <Toolbar className="mb-1" />
            <Editable
                className="form-control"
                style={{
                    minHeight: "100px",
                }}
                renderElement={renderElement}
                renderLeaf={renderLeaf}
                placeholder={placeholder}
                onKeyDown={onHotkeyDown(editor)}
                spellCheck
                readOnly={disabled}
            />
        </Slate>
    );
}
