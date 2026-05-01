# VulnerAI

Diccionario operativo de ataques y mitigaciones para sistemas basados en Large Language Models (LLMs).

**Demo:** [vulner-ai.vercel.app](https://vulner-ai.vercel.app)

---

## Descripción

VulnerAI cataloga 50 vulnerabilidades LLM clasificadas y mapeadas a los principales estándares de seguridad: OWASP LLM Top 10, MITRE ATLAS y NIST AI RMF. Cada ficha incluye descripción técnica, vectores de ataque, impacto CIA, mitigaciones, snippets de código y referencias bibliográficas.

## Secciones

| Página | Descripción |
|---|---|
| Inicio | Presentación del proyecto y acceso rápido al catálogo |
| Vulnerabilidades | Catálogo completo con búsqueda, filtros y ordenación |
| Comparador | Matriz de susceptibilidad vulnerabilidades × modelos |
| Snippets | Fragmentos de código de ataque y defensa por vulnerabilidad |
| Contribuir | Formulario para proponer nuevas vulnerabilidades |
| Administración | Panel de revisión y gestión de contribuciones |

## Stack

| Capa | Tecnología |
|---|---|
| Frontend | HTML5, CSS3, JavaScript ES6 (sin frameworks) |
| Backend | Supabase — PostgreSQL + RLS + Edge Functions |
| Despliegue | Vercel |

## Estructura del proyecto

```
/
├── assets/
│   ├── css/        # Estilos — design tokens, componentes y páginas
│   ├── js/         # Lógica de cada sección y utilidades compartidas
│   └── data/       # Datos estáticos — vulnerabilidades, modelos y snippets
├── supabase/
│   ├── schema.sql  # Esquema completo de la base de datos
│   └── functions/  # Edge Functions
└── *.html          # Páginas del sitio
```

## Autores

Samuel Muñoz Millán · [smm00156@red.ujaen.es](mailto:smm00156@red.ujaen.es)  
Carlos Alberto Ruiz Blanco · [carb0003@red.ujaen.es](mailto:carb0003@red.ujaen.es)

Universidad de Jaén · Ingeniería Informática · SIWEB 2026
