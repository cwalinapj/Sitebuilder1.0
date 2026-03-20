PRAGMA foreign_keys = ON;

-- Second-layer subtype catalog. Canonical business type remains the primary label;
-- subtype adds extra specificity for design, search, and content generation.

CREATE TABLE IF NOT EXISTS business_type_subtype_catalog (
  subtype_key TEXT PRIMARY KEY,
  canonical_type TEXT NOT NULL,
  display_label TEXT NOT NULL,
  category TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (canonical_type) REFERENCES business_type_catalog(canonical_type)
);

CREATE INDEX IF NOT EXISTS idx_business_type_subtype_catalog_canonical
ON business_type_subtype_catalog (canonical_type, subtype_key);

CREATE TABLE IF NOT EXISTS business_type_subtype_alias_catalog (
  alias_phrase TEXT PRIMARY KEY,
  subtype_key TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'seed',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (subtype_key) REFERENCES business_type_subtype_catalog(subtype_key)
);

CREATE INDEX IF NOT EXISTS idx_business_type_subtype_alias_catalog_subtype
ON business_type_subtype_alias_catalog (subtype_key, alias_phrase);

CREATE TABLE IF NOT EXISTS business_type_subtype_signal_catalog (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subtype_key TEXT NOT NULL,
  signal_type TEXT NOT NULL CHECK (
    signal_type IN (
      'statement_prefix',
      'statement_pattern',
      'strong_keyword',
      'weak_keyword',
      'negative_keyword',
      'profession',
      'service',
      'product',
      'industry_term'
    )
  ),
  value TEXT NOT NULL,
  normalized_value TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1.0,
  notes TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (subtype_key) REFERENCES business_type_subtype_catalog(subtype_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_business_type_subtype_signal_catalog_unique
ON business_type_subtype_signal_catalog (subtype_key, signal_type, normalized_value);

CREATE INDEX IF NOT EXISTS idx_business_type_subtype_signal_catalog_lookup
ON business_type_subtype_signal_catalog (subtype_key, signal_type, is_active);

CREATE INDEX IF NOT EXISTS idx_business_type_subtype_signal_catalog_value
ON business_type_subtype_signal_catalog (normalized_value, is_active);

INSERT OR REPLACE INTO business_type_subtype_catalog (
  subtype_key, canonical_type, display_label, category, is_active, created_at, updated_at
) VALUES
  ('pizzeria', 'restaurant', 'Pizzeria', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('steakhouse', 'restaurant', 'Steakhouse', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('seafood restaurant', 'restaurant', 'Seafood Restaurant', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('sushi restaurant', 'restaurant', 'Sushi Restaurant', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('vegan restaurant', 'restaurant', 'Vegan Restaurant', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('vegetarian cafe', 'cafe', 'Vegetarian Cafe', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('dessert shop', 'bakery', 'Dessert Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('ice cream parlor', 'bakery', 'Ice Cream Parlor', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('juice bar', 'cafe', 'Juice Bar', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('tea house', 'cafe', 'Tea House', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('wine bar', 'bar', 'Wine Bar', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('sports bar', 'bar', 'Sports Bar', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('cocktail lounge', 'bar', 'Cocktail Lounge', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('tapas bar', 'restaurant', 'Tapas Bar', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('brewpub', 'brewery', 'Brewpub', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('diner', 'restaurant', 'Diner', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('fast food restaurant', 'restaurant', 'Fast Food Restaurant', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('burger restaurant', 'restaurant', 'Burger Restaurant', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('sandwich shop', 'restaurant', 'Sandwich Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('bagel shop', 'bakery', 'Bagel Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('donut shop', 'bakery', 'Donut Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('cupcake bakery', 'bakery', 'Cupcake Bakery', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('waffle house', 'restaurant', 'Waffle House', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('soup and salad bar', 'restaurant', 'Soup & Salad Bar', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('smoothie and juice bar', 'cafe', 'Smoothie & Juice Bar', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('bubble tea shop', 'cafe', 'Bubble Tea Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('frozen yogurt shop', 'bakery', 'Frozen Yogurt Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('gelato shop', 'bakery', 'Gelato Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('candy store', 'grocery store', 'Candy Store', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('chocolate shop', 'bakery', 'Chocolate Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('cheese shop', 'grocery store', 'Cheese Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('spice shop', 'grocery store', 'Spice Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('butcher shop', 'grocery store', 'Butcher Shop', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('fish market', 'grocery store', 'Fish Market', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('farmers market vendor', 'grocery store', 'Farmers Market Vendor', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('meal prep service', 'catering business', 'Meal Prep Service', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('meal kit delivery business', 'catering business', 'Meal Kit Delivery Business', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('pop-up restaurant', 'restaurant', 'Pop-up Restaurant', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('distillery tasting room', 'bar', 'Distillery Tasting Room', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000),
  ('meadery', 'winery', 'Meadery', 'food_and_beverage_expansion', 1, 1742428800000, 1742428800000);

INSERT OR REPLACE INTO business_type_subtype_alias_catalog (
  alias_phrase, subtype_key, source, is_active, created_at, updated_at
) VALUES
  ('pizza place', 'pizzeria', 'seed', 1, 1742428800000, 1742428800000),
  ('pizza shop', 'pizzeria', 'seed', 1, 1742428800000, 1742428800000),
  ('steak restaurant', 'steakhouse', 'seed', 1, 1742428800000, 1742428800000),
  ('fish house', 'seafood restaurant', 'seed', 1, 1742428800000, 1742428800000),
  ('sushi bar', 'sushi restaurant', 'seed', 1, 1742428800000, 1742428800000),
  ('plant based restaurant', 'vegan restaurant', 'seed', 1, 1742428800000, 1742428800000),
  ('veggie restaurant', 'vegetarian cafe', 'seed', 1, 1742428800000, 1742428800000),
  ('sweets shop', 'dessert shop', 'seed', 1, 1742428800000, 1742428800000),
  ('ice cream shop', 'ice cream parlor', 'seed', 1, 1742428800000, 1742428800000),
  ('juice shop', 'juice bar', 'seed', 1, 1742428800000, 1742428800000),
  ('tea room', 'tea house', 'seed', 1, 1742428800000, 1742428800000),
  ('wine lounge', 'wine bar', 'seed', 1, 1742428800000, 1742428800000),
  ('bar lounge', 'cocktail lounge', 'seed', 1, 1742428800000, 1742428800000),
  ('brewery restaurant', 'brewpub', 'seed', 1, 1742428800000, 1742428800000),
  ('greasy spoon', 'diner', 'seed', 1, 1742428800000, 1742428800000),
  ('quick service restaurant', 'fast food restaurant', 'seed', 1, 1742428800000, 1742428800000),
  ('burger joint', 'burger restaurant', 'seed', 1, 1742428800000, 1742428800000),
  ('sub shop', 'sandwich shop', 'seed', 1, 1742428800000, 1742428800000),
  ('hoagie shop', 'sandwich shop', 'seed', 1, 1742428800000, 1742428800000),
  ('bagel bakery', 'bagel shop', 'seed', 1, 1742428800000, 1742428800000),
  ('doughnut shop', 'donut shop', 'seed', 1, 1742428800000, 1742428800000),
  ('cupcake shop', 'cupcake bakery', 'seed', 1, 1742428800000, 1742428800000),
  ('healthy lunch cafe', 'soup and salad bar', 'seed', 1, 1742428800000, 1742428800000),
  ('smoothie bar', 'smoothie and juice bar', 'seed', 1, 1742428800000, 1742428800000),
  ('boba shop', 'bubble tea shop', 'seed', 1, 1742428800000, 1742428800000),
  ('milk tea shop', 'bubble tea shop', 'seed', 1, 1742428800000, 1742428800000),
  ('froyo', 'frozen yogurt shop', 'seed', 1, 1742428800000, 1742428800000),
  ('italian ice cream shop', 'gelato shop', 'seed', 1, 1742428800000, 1742428800000),
  ('confectionery', 'candy store', 'seed', 1, 1742428800000, 1742428800000),
  ('chocolatier', 'chocolate shop', 'seed', 1, 1742428800000, 1742428800000),
  ('fromagerie', 'cheese shop', 'seed', 1, 1742428800000, 1742428800000),
  ('spice market', 'spice shop', 'seed', 1, 1742428800000, 1742428800000),
  ('meat market', 'butcher shop', 'seed', 1, 1742428800000, 1742428800000),
  ('fishmonger', 'fish market', 'seed', 1, 1742428800000, 1742428800000),
  ('local farmer', 'farmers market vendor', 'seed', 1, 1742428800000, 1742428800000),
  ('prepared meals', 'meal prep service', 'seed', 1, 1742428800000, 1742428800000),
  ('subscription meal kits', 'meal kit delivery business', 'seed', 1, 1742428800000, 1742428800000),
  ('food pop up', 'pop-up restaurant', 'seed', 1, 1742428800000, 1742428800000),
  ('craft distillery', 'distillery tasting room', 'seed', 1, 1742428800000, 1742428800000),
  ('honey wine', 'meadery', 'seed', 1, 1742428800000, 1742428800000);

INSERT OR REPLACE INTO business_type_subtype_signal_catalog (
  subtype_key, signal_type, value, normalized_value, weight, notes, is_active, created_at, updated_at
) VALUES
  ('pizzeria', 'strong_keyword', 'pizza', 'pizza', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('pizzeria', 'strong_keyword', 'calzones', 'calzones', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('steakhouse', 'strong_keyword', 'steakhouse', 'steakhouse', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('steakhouse', 'industry_term', 'ribeye', 'ribeye', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('seafood restaurant', 'strong_keyword', 'oysters', 'oysters', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('seafood restaurant', 'strong_keyword', 'crab', 'crab', 2.0, NULL, 1, 1742428800000, 1742428800000),
  ('sushi restaurant', 'strong_keyword', 'sashimi', 'sashimi', 2.7, NULL, 1, 1742428800000, 1742428800000),
  ('sushi restaurant', 'strong_keyword', 'nigiri', 'nigiri', 2.7, NULL, 1, 1742428800000, 1742428800000),
  ('vegan restaurant', 'strong_keyword', 'vegan', 'vegan', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('vegan restaurant', 'industry_term', 'plant based', 'plant based', 2.5, NULL, 1, 1742428800000, 1742428800000),
  ('vegetarian cafe', 'strong_keyword', 'vegetarian', 'vegetarian', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('dessert shop', 'strong_keyword', 'dessert shop', 'dessert shop', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('dessert shop', 'product', 'sweets', 'sweets', 2.1, NULL, 1, 1742428800000, 1742428800000),
  ('ice cream parlor', 'strong_keyword', 'gelato', 'gelato', 2.7, NULL, 1, 1742428800000, 1742428800000),
  ('ice cream parlor', 'product', 'sundaes', 'sundaes', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('juice bar', 'strong_keyword', 'cold pressed', 'cold pressed', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('juice bar', 'product', 'smoothies', 'smoothies', 2.1, NULL, 1, 1742428800000, 1742428800000),
  ('tea house', 'strong_keyword', 'loose leaf teas', 'loose leaf teas', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('wine bar', 'industry_term', 'pairings', 'pairings', 2.0, NULL, 1, 1742428800000, 1742428800000),
  ('sports bar', 'industry_term', 'game day', 'game day', 2.1, NULL, 1, 1742428800000, 1742428800000),
  ('cocktail lounge', 'strong_keyword', 'mixology', 'mixology', 2.6, NULL, 1, 1742428800000, 1742428800000),
  ('cocktail lounge', 'product', 'martinis', 'martinis', 2.0, NULL, 1, 1742428800000, 1742428800000),
  ('tapas bar', 'industry_term', 'small plates', 'small plates', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('tapas bar', 'industry_term', 'sangria', 'sangria', 1.9, NULL, 1, 1742428800000, 1742428800000),
  ('brewpub', 'strong_keyword', 'brewpub', 'brewpub', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('diner', 'strong_keyword', 'breakfast all day', 'breakfast all day', 2.5, NULL, 1, 1742428800000, 1742428800000),
  ('fast food restaurant', 'industry_term', 'drive thru', 'drive thru', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('fast food restaurant', 'product', 'fries', 'fries', 1.6, NULL, 1, 1742428800000, 1742428800000),
  ('burger restaurant', 'strong_keyword', 'burgers', 'burgers', 2.5, NULL, 1, 1742428800000, 1742428800000),
  ('burger restaurant', 'product', 'sliders', 'sliders', 2.1, NULL, 1, 1742428800000, 1742428800000),
  ('sandwich shop', 'strong_keyword', 'subs', 'subs', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('sandwich shop', 'industry_term', 'deli sandwiches', 'deli sandwiches', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('bagel shop', 'strong_keyword', 'bagels', 'bagels', 2.7, NULL, 1, 1742428800000, 1742428800000),
  ('donut shop', 'strong_keyword', 'donuts', 'donuts', 2.7, NULL, 1, 1742428800000, 1742428800000),
  ('cupcake bakery', 'strong_keyword', 'cupcakes', 'cupcakes', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('waffle house', 'strong_keyword', 'waffles', 'waffles', 2.6, NULL, 1, 1742428800000, 1742428800000),
  ('soup and salad bar', 'strong_keyword', 'salad bar', 'salad bar', 2.7, NULL, 1, 1742428800000, 1742428800000),
  ('soup and salad bar', 'product', 'healthy lunch', 'healthy lunch', 1.9, NULL, 1, 1742428800000, 1742428800000),
  ('smoothie and juice bar', 'strong_keyword', 'smoothie bar', 'smoothie bar', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('bubble tea shop', 'strong_keyword', 'boba', 'boba', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('bubble tea shop', 'product', 'milk tea', 'milk tea', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('frozen yogurt shop', 'strong_keyword', 'frozen yogurt', 'frozen yogurt', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('gelato shop', 'strong_keyword', 'gelato', 'gelato', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('candy store', 'strong_keyword', 'candy store', 'candy store', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('chocolate shop', 'strong_keyword', 'artisan chocolates', 'artisan chocolates', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('cheese shop', 'strong_keyword', 'charcuterie', 'charcuterie', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('spice shop', 'strong_keyword', 'spices', 'spices', 2.5, NULL, 1, 1742428800000, 1742428800000),
  ('butcher shop', 'strong_keyword', 'butcher shop', 'butcher shop', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('fish market', 'strong_keyword', 'fish market', 'fish market', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('farmers market vendor', 'industry_term', 'farmers market', 'farmers market', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('meal prep service', 'service', 'meal prep', 'meal prep', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('meal prep service', 'service', 'prepared meals', 'prepared meals', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('meal kit delivery business', 'service', 'meal kits', 'meal kits', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('meal kit delivery business', 'industry_term', 'subscription meals', 'subscription meals', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('pop-up restaurant', 'strong_keyword', 'pop up restaurant', 'pop up restaurant', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('distillery tasting room', 'industry_term', 'spirits', 'spirits', 2.3, NULL, 1, 1742428800000, 1742428800000),
  ('distillery tasting room', 'industry_term', 'whiskey', 'whiskey', 2.3, NULL, 1, 1742428800000, 1742428800000),
  ('meadery', 'strong_keyword', 'mead', 'mead', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('meadery', 'industry_term', 'honey wine', 'honey wine', 2.4, NULL, 1, 1742428800000, 1742428800000);
