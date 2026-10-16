/**
 * Sentinel AI - 3D Toroidal Metallic Coil Background
 * Powered by Three.js (Air-Gapped & Local)
 *
 * Implements the metallic coiled torus / slinky-ring animation from the
 * reference video with specular mint/cyan key lights and warm orange accents.
 */

import * as THREE from '../vendor/three.module.min.js';

class ToroidalHelixCurve extends THREE.Curve {
  constructor(majorR = 7.2, minorR = 2.4, coils = 48) {
    super();
    this.majorR = majorR;
    this.minorR = minorR;
    this.coils = coils;
  }

  getPoint(t, optionalTarget = new THREE.Vector3()) {
    const angle = t * Math.PI * 2;
    const coilAngle = angle * this.coils;
    
    const r = this.majorR + this.minorR * Math.cos(coilAngle);
    const x = r * Math.cos(angle);
    const y = this.minorR * Math.sin(coilAngle);
    const z = r * Math.sin(angle);

    return optionalTarget.set(x, y, z);
  }
}

export class Background3D {
  constructor(canvasId = 'bgCanvas3D', containerId = 'bg3dContainer') {
    this.canvas = document.getElementById(canvasId);
    this.container = document.getElementById(containerId);
    this.isInitialized = false;
    this.animId = null;
    
    // Mouse Parallax
    this.mouse = { x: 0, y: 0, targetX: 0, targetY: 0 };
    this.onPointerMove = this.onPointerMove.bind(this);
    this.onResize = this.onResize.bind(this);
  }

  init() {
    if (!this.canvas) {
      console.warn('[Background3D] Canvas element not found.');
      return;
    }

    try {
      // 1. Scene & Camera Setup
      this.scene = new THREE.Scene();
      this.scene.fog = new THREE.FogExp2(0x0A1517, 0.022);

      const width = window.innerWidth;
      const height = window.innerHeight;
      
      this.camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
      this.camera.position.set(0, 2, 22);

      // 2. Local Renderer
      this.renderer = new THREE.WebGLRenderer({
        canvas: this.canvas,
        alpha: true,
        antialias: true,
        powerPreference: 'high-performance'
      });
      this.renderer.setSize(width, height);
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
      this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
      this.renderer.toneMappingExposure = 1.15;

      // 3. Lighting Setup (Mint Key + Cyan Fill + Warm Orange Rim)
      this.setupLights();

      // 4. Geometry & Objects
      this.setupSculpture();

      // 5. Floating Dust Particles
      this.setupDustParticles();

      // 6. Event Listeners
      window.addEventListener('pointermove', this.onPointerMove, { passive: true });
      window.addEventListener('resize', this.onResize, { passive: true });

      // 7. Check for reduced motion
      const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (prefersReducedMotion) {
        this.renderStaticFrame();
      } else {
        this.animate();
      }

      this.isInitialized = true;
    } catch (err) {
      console.error('[Background3D] Failed to initialize 3D scene:', err);
    }
  }

  setupLights() {
    // Ambient Light - dark teal
    const ambientLight = new THREE.AmbientLight(0x0E2426, 2.0);
    this.scene.add(ambientLight);

    // Key Light 1: Luminescent Mint (Top-Left Forward)
    this.keyLightMint = new THREE.PointLight(0x69E2C2, 4.5, 45, 1.2);
    this.keyLightMint.position.set(-14, 16, 12);
    this.scene.add(this.keyLightMint);

    // Fill Light 2: Electric Cyan (Top-Right Forward)
    this.fillLightCyan = new THREE.PointLight(0x65D9DF, 3.8, 45, 1.2);
    this.fillLightCyan.position.set(16, 10, 8);
    this.scene.add(this.fillLightCyan);

    // Rim/Under Light 3: Warm Orange Glow (Bottom-Center Back)
    this.rimLightOrange = new THREE.PointLight(0xFF8057, 2.8, 40, 1.4);
    this.rimLightOrange.position.set(0, -14, -6);
    this.scene.add(this.rimLightOrange);

    // Subtle Front Center Spotlight
    const spotLight = new THREE.SpotLight(0xA8F5E1, 1.8);
    spotLight.position.set(0, 12, 18);
    spotLight.angle = Math.PI / 4;
    spotLight.penumbra = 0.8;
    this.scene.add(spotLight);
  }

  setupSculpture() {
    this.sculptureGroup = new THREE.Group();

    // Toroidal Metallic Spring/Coil
    const helixCurve = new ToroidalHelixCurve(7.2, 2.3, 52);
    const coilGeometry = new THREE.TubeGeometry(helixCurve, 1200, 0.08, 10, true);

    const metallicTealMat = new THREE.MeshStandardMaterial({
      color: 0x163F44,
      metalness: 0.94,
      roughness: 0.20,
      envMapIntensity: 1.2
    });

    this.coilMesh = new THREE.Mesh(coilGeometry, metallicTealMat);
    this.sculptureGroup.add(this.coilMesh);

    // Inner Core Accent Ring (Delicate guide ring)
    const innerRingGeo = new THREE.TorusGeometry(7.2, 0.035, 16, 100);
    const innerRingMat = new THREE.MeshStandardMaterial({
      color: 0x69E2C2,
      emissive: 0x228B78,
      emissiveIntensity: 0.4,
      metalness: 0.9,
      roughness: 0.15
    });
    const innerRing = new THREE.Mesh(innerRingGeo, innerRingMat);
    innerRing.rotation.x = Math.PI / 2;
    this.sculptureGroup.add(innerRing);

    // Initial cinematic tilt
    this.sculptureGroup.rotation.x = 0.55;
    this.sculptureGroup.rotation.y = 0.35;
    this.sculptureGroup.position.set(2.5, 0, -2);

    this.scene.add(this.sculptureGroup);
  }

  setupDustParticles() {
    const particleCount = 140;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 36;
      positions[i + 1] = (Math.random() - 0.5) * 28;
      positions[i + 2] = (Math.random() - 0.5) * 20 - 4;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const material = new THREE.PointsMaterial({
      color: 0x65D9DF,
      size: 0.09,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending
    });

    this.particles = new THREE.Points(geometry, material);
    this.scene.add(this.particles);
  }

  onPointerMove(e) {
    this.mouse.targetX = (e.clientX / window.innerWidth - 0.5) * 0.3;
    this.mouse.targetY = (e.clientY / window.innerHeight - 0.5) * 0.25;
  }

  onResize() {
    if (!this.camera || !this.renderer) return;
    const width = window.innerWidth;
    const height = window.innerHeight;

    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();

    this.renderer.setSize(width, height);
  }

  animate() {
    this.animId = requestAnimationFrame(() => this.animate());

    // Smooth mouse lerp
    this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.04;
    this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.04;

    if (this.sculptureGroup) {
      // Continuous slow cinematic spin
      this.sculptureGroup.rotation.y += 0.0022;
      this.sculptureGroup.rotation.z += 0.0008;

      // Parallax reaction
      this.sculptureGroup.rotation.x = 0.55 + this.mouse.y * 0.3;
      this.sculptureGroup.position.x = 2.5 + this.mouse.x * 1.5;
      this.sculptureGroup.position.y = -this.mouse.y * 1.2;
    }

    if (this.particles) {
      this.particles.rotation.y += 0.0004;
    }

    this.renderer.render(this.scene, this.camera);
  }

  renderStaticFrame() {
    if (this.renderer && this.scene && this.camera) {
      this.renderer.render(this.scene, this.camera);
    }
  }

  destroy() {
    if (this.animId) cancelAnimationFrame(this.animId);
    window.removeEventListener('pointermove', this.onPointerMove);
    window.removeEventListener('resize', this.onResize);
    if (this.renderer) this.renderer.dispose();
  }
}

let instance = null;

export function initBackground3D() {
  if (!instance) {
    instance = new Background3D();
    instance.init();
  }
  return instance;
}
