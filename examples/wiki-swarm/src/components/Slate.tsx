import React, { } from 'react'
import { RenderElementProps, RenderLeafProps, useSlate } from 'slate-react'
import {
    Editor,
    Transforms,
    Element as SlateElement,
    Descendant,
} from 'slate'
import Button from 'react-bootstrap/esm/Button';
import { TypeBold, TypeItalic, TypeUnderline, Code, TypeH1, TypeH2, BlockquoteLeft, ListOl, ListUl } from 'react-bootstrap-icons';
import { CustomElementType, FormattedTextMarks } from '../slate';

// const HOTKEYS = {
//     'mod+b': 'bold',
//     'mod+i': 'italic',
//     'mod+u': 'underline',
//     'mod+`': 'code',
//     'mod+t': 'table',
//     'mod+y': 'checkbox',
//     'mod+g': 'dropdown',
//     'mod+k': 'radio',
// }

const LIST_TYPES = ['numbered-list', 'bulleted-list'];

function toggleBlock(editor: Editor, format: CustomElementType) {
    const isActive = isBlockActive(editor, format)
    const isList = LIST_TYPES.includes(format)

    Transforms.unwrapNodes(editor, {
        match: n =>
            LIST_TYPES.includes(
                (!Editor.isEditor(n) && SlateElement.isElement(n) && n.type) || ''
            ),
        split: true,
    })
    const newProperties: Partial<SlateElement> = {
        type: (isActive ? 'paragraph' : isList ? 'list-item' : format) || '',
    }
    Transforms.setNodes<SlateElement>(editor, newProperties)

    if (!isActive && isList) {
        const block = { type: format, children: [] }
        Transforms.wrapNodes(editor, block)
    }
}

function toggleMark(editor: Editor, format: FormattedTextMarks) {
    const isActive = isMarkActive(editor, format)

    if (isActive) {
        Editor.removeMark(editor, format)
    } else {
        Editor.addMark(editor, format, true)
    }
}

function isBlockActive(editor: Editor, format: CustomElementType) {
    const [match] = Editor.nodes(editor, {
        match: n =>
            !Editor.isEditor(n) && SlateElement.isElement(n) && n.type === format,
    })

    return !!match
}

function isMarkActive(editor: Editor, format: FormattedTextMarks) {
    const marks = Editor.marks(editor)
    return marks ? marks[format] === true : false
}

export function Element({ attributes, children, element }: RenderElementProps) {
    switch (element.type) {
        case 'block-quote':
            return <blockquote {...attributes}>{children}</blockquote>
        case 'bulleted-list':
            return <ul {...attributes}>{children}</ul>
        case 'heading-one':
            return <h1 {...attributes}>{children}</h1>
        case 'heading-two':
            return <h2 {...attributes}>{children}</h2>
        case 'list-item':
            return <li {...attributes}>{children}</li>
        case 'numbered-list':
            return <ol {...attributes}>{children}</ol>
        case 'paragraph':
        default:
            return <p {...attributes}>{children}</p>
    }
}

export function Leaf({ attributes, children, leaf }: RenderLeafProps) {
    if (leaf.bold) {
        children = <strong>{children}</strong>
    }

    if (leaf.code) {
        children = <code>{children}</code>
    }

    if (leaf.italic) {
        children = <em>{children}</em>
    }

    if (leaf.underline) {
        children = <u>{children}</u>
    }

    return <span {...attributes}>{children}</span>
}

export function BlockButton({ format, children }: {
    format: CustomElementType;
    children?: React.ReactNode;
}) {
    const editor = useSlate()
    return (
        <Button
            active={isBlockActive(editor, format)}
            onMouseDown={event => {
                event.preventDefault()
                toggleBlock(editor, format)
            }}
        >
            {children}
        </Button>
    )
}

export function MarkButton({ format, children }: {
    format: FormattedTextMarks;
    children?: React.ReactNode;
}) {
    const editor = useSlate()
    return (
        <Button
            active={isMarkActive(editor, format)}
            onMouseDown={event => {
                event.preventDefault()
                toggleMark(editor, format)
            }}
        >
            {children}
        </Button>
    )
}

export function Toolbar({ className }: {
    className?: string;
}) {
    return <div className={className}>
        <MarkButton format="bold">
            <TypeBold />
        </MarkButton>
        &nbsp;
        <MarkButton format="italic">
            <TypeItalic />
        </MarkButton>
        &nbsp;
        <MarkButton format="underline">
            <TypeUnderline />
        </MarkButton>
        &nbsp;
        <MarkButton format="code">
            <Code />
        </MarkButton>
        &nbsp;
        &nbsp;
        &nbsp;
        <BlockButton format="heading-one">
            <TypeH1 />
        </BlockButton>
        &nbsp;
        <BlockButton format="heading-two">
            <TypeH2 />
        </BlockButton>
        &nbsp;
        <BlockButton format="block-quote">
            <BlockquoteLeft />
        </BlockButton>
        &nbsp;
        <BlockButton format="numbered-list">
            <ListOl />
        </BlockButton>
        &nbsp;
        <BlockButton format="bulleted-list">
            <ListUl />
        </BlockButton>
    </div>
}

export function onHotkeyDown(editor: Editor) {
    return (event: React.KeyboardEvent<HTMLDivElement>) => {
        if (event.ctrlKey && event.key === "b") {
            toggleMark(editor, "bold");
            event.preventDefault();
        } else if (event.ctrlKey && event.key === "i") {
            toggleMark(editor, "italic");
            event.preventDefault();
        } else if (event.ctrlKey && event.key === "u") {
            toggleMark(editor, "underline");
            event.preventDefault();
        } else if (event.ctrlKey && event.key === "`") {
            toggleMark(editor, "code");
            event.preventDefault();
        }
    };
}

export const initialValue: Descendant[] = [
    {
        type: 'paragraph',
        children: [
            { text: 'This is editable ' },
            { text: 'rich', bold: true },
            { text: ' text, ' },
            { text: 'much', italic: true },
            { text: ' better than a ' },
            { text: '<textarea>', code: true },
            { text: '!' },
        ],
    },
    {
        type: 'paragraph',
        children: [
            {
                text:
                    "Since it's rich text, you can do things like turn a selection of text ",
            },
            { text: 'bold', bold: true },
            {
                text:
                    ', or add a semantically rendered block quote in the middle of the page, like this:',
            },
        ],
    },
    {
        type: 'block-quote',
        children: [{ text: 'A wise quote.' }],
    },
    {
        type: 'paragraph',
        children: [{ text: 'Try it out for yourself!' }],
    },
]
