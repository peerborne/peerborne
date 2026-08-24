/**
 * Generate a mock wiki article document.
 */
export function generateWikiArticle(id: number): Record<string, unknown> {
  const categories = ['Technology', 'Science', 'History', 'Art', 'Music'];
  const authors = ['Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank', 'Grace', 'Hank'];

  return {
    title: `Article ${id}: ${randomTitle(id)}`,
    content: `This is the content of article ${id}. `.repeat(10),
    author: authors[id % authors.length],
    category: categories[id % categories.length],
    createdOn: new Date(2024, 0, 1 + (id % 365)).toISOString(),
    tags: [`tag-${id % 10}`, `tag-${id % 5}`],
    viewCount: id * 7 % 1000,
  };
}

/**
 * Generate a mock password entry document.
 */
export function generatePasswordEntry(id: number): Record<string, unknown> {
  const categories = ['Social', 'Email', 'Banking', 'Shopping', 'Work'];
  return {
    name: `Entry ${id}`,
    url: `https://example-${id}.com`,
    username: `user${id}@example.com`,
    category: categories[id % categories.length],
    createdOn: new Date(2024, 0, 1 + (id % 365)).toISOString(),
  };
}

/**
 * Generate a map of documents for benchmarking.
 */
export function generateDocuments(
  type: 'wiki' | 'password',
  count: number,
): Map<string, Record<string, unknown>> {
  const docs = new Map<string, Record<string, unknown>>();
  const prefix = type === 'wiki' ? '/articles/' : '/passwords/';
  const generator = type === 'wiki' ? generateWikiArticle : generatePasswordEntry;

  for (let i = 0; i < count; i++) {
    docs.set(`${prefix}${i}`, generator(i));
  }

  return docs;
}

function randomTitle(seed: number): string {
  const words = [
    'Introduction', 'Guide', 'Overview', 'Analysis', 'Review',
    'Deep', 'Dive', 'Quick', 'Advanced', 'Beginner',
    'Modern', 'Classic', 'Essential', 'Complete', 'Practical',
  ];
  const w1 = words[seed % words.length];
  const w2 = words[(seed * 7 + 3) % words.length];
  return `${w1} ${w2}`;
}
