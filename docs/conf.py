# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
project = 'Telegen'
copyright = '2026, Telegen Authors'
author = 'Telegen Authors'
release = '2.0.0'
version = '2.0'

# -- General configuration ---------------------------------------------------
extensions = [
    'myst_parser',
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx_copybutton',
    'sphinx_design',
    'sphinxcontrib.mermaid',
]

# MyST Parser configuration
myst_enable_extensions = [
    'colon_fence',
    'deflist',
    'fieldlist',
    'html_admonition',
    'html_image',
    'replacements',
    'smartquotes',
    'strikethrough',
    'substitution',
    'tasklist',
]

myst_heading_anchors = 3

# Source file suffixes
source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

# The master toctree document
master_doc = 'index'

# Templates path
templates_path = ['_templates']

# Patterns to exclude
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'

html_theme_options = {
    'logo_only': False,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': True,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False,
}

html_static_path = ['_static']

# Custom CSS
html_css_files = [
    'custom.css',
]

# -- Options for intersphinx -------------------------------------------------
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}

# -- Options for copybutton --------------------------------------------------
copybutton_prompt_text = r'^\$ |^>>> |^> '
copybutton_prompt_is_regexp = True

# -- Options for mermaid -----------------------------------------------------
mermaid_version = 'latest'
