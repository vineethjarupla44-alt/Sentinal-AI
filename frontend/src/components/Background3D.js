/**
 * TraceGuard - 3D Toroidal Metallic Coil Background
 * Powered by Three.js (Air-Gapped & Local)
 *
 * Implements the sculptural metallic coiled spring / toroidal helix from the
 * reference video:
 * - Thick, rounded, interlocking metallic loops (tubeRadius: 0.32, coils: 28)
 * - Deep dark petrol teal metallic base material with liquid clearcoat
 * - Procedural studio reflection environment for realistic metallic highlights
 * - Vibrant luminescent mint and turquoise illumination on the inner curves
 * - Soft shadows and occlusion between interlocking loops
 * - Silky smooth, continuous cinematic rotation with gentle floating motion
 * - Respects prefers-reduced-motion and document.visibilityState
 */

import * as THREE from '../vendor/three.module.min.js';

/**
 * Parametric Toroidal Helix Curve
 * Generates a coiled spring wrapped uniformly around a central torus ring.
 */
class ToroidalHelixCurve extends THREE.Curve {
  constructor(majorR = 7.0, minorR = 2.2, coils = 28) {
    super();
    this.majorR = majorR;
    this.minorR = minorR;
    this.coils = coils;
  }

  getPoint(t, optionalTarget = new THREE.Vector3()) {
    const angle = t * Math.PI * 2;
    const coilAngle = angle * this.coils;
    
    // Position on the torus surface
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
    this.isPageVisible = true;
    
    // Base orientation & positioning (Center-right background focal point)
    this.basePosX = 2.6;
    this.basePosY = 0.2;
    this.basePosZ = -2.0;
    this.baseRotX = 0.46;
    this.baseRotY = -0.26;
    this.baseRotZ = 0.10;

    // Mouse Parallax
    this.mouse = { x: 0, y: 0, targetX: 0, targetY: 0 };
    this.onPointerMove = this.onPointerMove.bind(this);
    this.onResize = this.onResize.bind(this);
    this.onVisibilityChange = this.onVisibilityChange.bind(this);
  }

  init() {
    if (!this.canvas) {
      console.warn('[Background3D] Canvas element not found.');
      return;
    }

    try {
      // 1. Scene & Atmosphere Setup
      this.scene = new THREE.Scene();
      this.scene.fog = new THREE.FogExp2(0x0A1517, 0.022);

      const width = window.innerWidth;
      const height = window.innerHeight;
      
      this.camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 100);
      this.camera.position.set(0, 1.8, 21);

      // 2. High-Performance Renderer
      this.renderer = new THREE.WebGLRenderer({
        canvas: this.canvas,
        alpha: true,
        antialias: true,
        powerPreference: 'high-performance',
        stencil: false
      });
      this.renderer.setSize(width, height);
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
      this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
      this.renderer.toneMappingExposure = 1.25;

      // Enable soft shadow mapping for inter-loop occlusion
      this.renderer.shadowMap.enabled = true;
      this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;

      // 3. Procedural Studio Environment Map for realistic metallic sheen
      this.setupStudioEnvironment();

      // 4. Multi-Point Emissive Lighting System
      this.setupLights();

      // 5. 3D Sculptural Coil Geometry
      this.setupSculpture();

      // 6. Subtle Ambient Stardust
      this.setupDustParticles();

      // 7. Event Listeners
      window.addEventListener('pointermove', this.onPointerMove, { passive: true });
      window.addEventListener('resize', this.onResize, { passive: true });
      document.addEventListener('visibilitychange', this.onVisibilityChange);

      // 8. Motion Preference Verification
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

  /**
   * Generates a procedural high-dynamic-range reflection texture
   * giving the metallic coil luxurious, smooth reflections without external HDR files.
   */
  setupStudioEnvironment() {
    try {
      const envCanvas = document.createElement('canvas');
      envCanvas.width = 512;
      envCanvas.height = 256;
      const ctx = envCanvas.getContext('2d');

      // Base dark teal studio space
      const bgGrad = ctx.createLinearGradient(0, 0, 0, 256);
      bgGrad.addColorStop(0, '#041012');
      bgGrad.addColorStop(0.5, '#0A1D20');
      bgGrad.addColorStop(1, '#061315');
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, 512, 256);

      // Softbox 1: Mint Key Light reflection (Top Left)
      const mintGrad = ctx.createRadialGradient(160, 60, 10, 160, 60, 140);
      mintGrad.addColorStop(0, 'rgba(105, 226, 194, 0.95)');
      mintGrad.addColorStop(0.4, 'rgba(101, 217, 223, 0.45)');
      mintGrad.addColorStop(1, 'rgba(10, 29, 32, 0)');
      ctx.fillStyle = mintGrad;
      ctx.fillRect(0, 0, 320, 160);

      // Softbox 2: Cyan Fill Light reflection (Top Right)
      const cyanGrad = ctx.createRadialGradient(380, 80, 10, 380, 80, 120);
      cyanGrad.addColorStop(0, 'rgba(101, 217, 223, 0.85)');
      cyanGrad.addColorStop(0.5, 'rgba(74, 222, 128, 0.3)');
      cyanGrad.addColorStop(1, 'rgba(10, 29, 32, 0)');
      ctx.fillStyle = cyanGrad;
      ctx.fillRect(240, 0, 272, 180);

      // Softbox 3: Warm Coral Rim reflection (Bottom Center)
      const rimGrad = ctx.createRadialGradient(256, 220, 5, 256, 220, 100);
      rimGrad.addColorStop(0, 'rgba(255, 128, 87, 0.6)');
      rimGrad.addColorStop(0.6, 'rgba(255, 128, 87, 0.15)');
      rimGrad.addColorStop(1, 'rgba(10, 29, 32, 0)');
      ctx.fillStyle = rimGrad;
      ctx.fillRect(120, 150, 272, 106);

      const envTexture = new THREE.CanvasTexture(envCanvas);
      envTexture.mapping = THREE.EquirectangularReflectionMapping;

      const pmremGenerator = new THREE.PMREMGenerator(this.renderer);
      pmremGenerator.compileEquirectangularShader();
      const envMap = pmremGenerator.fromEquirectangular(envTexture).texture;
      this.scene.environment = envMap;

      envTexture.dispose();
      pmremGenerator.dispose();
    } catch (e) {
      console.warn('[Background3D] PMREM studio environment fallback:', e);
    }
  }

  setupLights() {
    // 1. Ambient Light - deep petrol teal
    const ambientLight = new THREE.AmbientLight(0x061A1D, 1.8);
    this.scene.add(ambientLight);

    // 2. INNER CORE LIGHT 1: Luminescent Mint inside the coil's central void
    // Directly illuminates the inner curves and crevices of the loops
    this.innerMintLight = new THREE.PointLight(0x69E2C2, 6.2, 22, 1.2);
    this.innerMintLight.position.set(0, 0, 0);
    this.scene.add(this.innerMintLight);

    // 3. INNER CORE LIGHT 2: Electric Cyan forward-offset point light
    this.innerCyanLight = new THREE.PointLight(0x65D9DF, 4.5, 24, 1.2);
    this.innerCyanLight.position.set(1.5, 1.0, 3.0);
    this.scene.add(this.innerCyanLight);

    // 4. Directional Key Light with Soft Shadows (Top-Left Forward)
    this.keyLightMint = new THREE.DirectionalLight(0x69E2C2, 2.4);
    this.keyLightMint.position.set(-12, 15, 14);
    this.keyLightMint.castShadow = true;
    this.keyLightMint.shadow.mapSize.width = 1024;
    this.keyLightMint.shadow.mapSize.height = 1024;
    this.keyLightMint.shadow.camera.near = 5;
    this.keyLightMint.shadow.camera.far = 40;
    this.keyLightMint.shadow.camera.left = -12;
    this.keyLightMint.shadow.camera.right = 12;
    this.keyLightMint.shadow.camera.top = 12;
    this.keyLightMint.shadow.camera.bottom = -12;
    this.keyLightMint.shadow.bias = -0.001;
    this.scene.add(this.keyLightMint);

    // 5. Fill Light (Right Front)
    const fillLight = new THREE.PointLight(0x65D9DF, 3.2, 35, 1.3);
    fillLight.position.set(15, 8, 10);
    this.scene.add(fillLight);

    // 6. Warm Coral Rim Light (Bottom-Right Back) - authentic TraceGuard chromatic accent
    this.rimLightCoral = new THREE.PointLight(0xFF8057, 3.8, 35, 1.3);
    this.rimLightCoral.position.set(8, -12, -6);
    this.scene.add(this.rimLightCoral);
  }

  setupSculpture() {
    this.sculptureGroup = new THREE.Group();
    this.coilGroup = new THREE.Group();

    // 1. SCULPTURAL METALLIC COIL (Thick, rounded, tactile loops)
    // majorR: 7.0, minorR: 2.2, coils: 28 loops, tubeRadius: 0.32
    const helixCurve = new ToroidalHelixCurve(7.0, 2.2, 28);
    const coilGeometry = new THREE.TubeGeometry(helixCurve, 1600, 0.32, 28, true);

    const metallicTealMat = new THREE.MeshPhysicalMaterial({
      color: 0x0E2C30,
      metalness: 0.92,
      roughness: 0.22,
      clearcoat: 0.55,
      clearcoatRoughness: 0.16,
      reflectivity: 0.95,
      envMapIntensity: 1.6
    });

    this.coilMesh = new THREE.Mesh(coilGeometry, metallicTealMat);
    this.coilMesh.castShadow = true;
    this.coilMesh.receiveShadow = true;
    this.coilGroup.add(this.coilMesh);

    // 2. INNER STRUCTURAL GUIDE CORE (Dark metallic central spine rail)
    const coreRailGeo = new THREE.TorusGeometry(7.0, 0.11, 20, 140);
    const coreRailMat = new THREE.MeshStandardMaterial({
      color: 0x07191C,
      metalness: 0.95,
      roughness: 0.35,
      envMapIntensity: 1.2
    });
    const coreRail = new THREE.Mesh(coreRailGeo, coreRailMat);
    coreRail.rotation.x = Math.PI / 2;
    coreRail.receiveShadow = true;
    this.coilGroup.add(coreRail);

    // 3. INNER LUMINESCENT BEZEL (Glow ring inside the central void)
    const innerBezelGeo = new THREE.TorusGeometry(4.4, 0.08, 16, 120);
    const innerBezelMat = new THREE.MeshStandardMaterial({
      color: 0x69E2C2,
      emissive: 0x69E2C2,
      emissiveIntensity: 0.75,
      metalness: 0.7,
      roughness: 0.2
    });
    const innerBezel = new THREE.Mesh(innerBezelGeo, innerBezelMat);
    innerBezel.rotation.x = Math.PI / 2;
    this.coilGroup.add(innerBezel);

    // Add coil group to master sculpture
    this.sculptureGroup.add(this.coilGroup);

    // Initial cinematic 3D orientation
    this.sculptureGroup.position.set(this.basePosX, this.basePosY, this.basePosZ);
    this.sculptureGroup.rotation.set(this.baseRotX, this.baseRotY, this.baseRotZ);

    this.scene.add(this.sculptureGroup);
  }

  setupDustParticles() {
    const particleCount = 120;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 38;
      positions[i + 1] = (Math.random() - 0.5) * 28;
      positions[i + 2] = (Math.random() - 0.5) * 18 - 4;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const material = new THREE.PointsMaterial({
      color: 0x65D9DF,
      size: 0.08,
      transparent: true,
      opacity: 0.35,
      blending: THREE.AdditiveBlending
    });

    this.particles = new THREE.Points(geometry, material);
    this.scene.add(this.particles);
  }

  onPointerMove(e) {
    this.mouse.targetX = (e.clientX / window.innerWidth - 0.5) * 0.35;
    this.mouse.targetY = (e.clientY / window.innerHeight - 0.5) * 0.30;
  }

  onResize() {
    if (!this.camera || !this.renderer) return;
    const width = window.innerWidth;
    const height = window.innerHeight;

    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();

    this.renderer.setSize(width, height);
  }

  onVisibilityChange() {
    this.isPageVisible = !document.hidden;
    if (this.isPageVisible && !this.animId) {
      this.animate();
    }
  }

  animate() {
    if (!this.isPageVisible) {
      this.animId = null;
      return;
    }

    this.animId = requestAnimationFrame(() => this.animate());

    // Smooth mouse lerp
    this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.04;
    this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.04;

    const time = performance.now() * 0.001;

    // 1. Rotate the coil around its own circular axis (Continuous hypnotic revolution)
    if (this.coilMesh) {
      this.coilMesh.rotation.y += 0.0022;
    }

    // 2. Sculptural floating motion & dynamic tilt
    if (this.sculptureGroup) {
      // Gentle breathing precession
      this.sculptureGroup.rotation.x = this.baseRotX + Math.sin(time * 0.45) * 0.035 + this.mouse.y * 0.22;
      this.sculptureGroup.rotation.y = this.baseRotY + Math.cos(time * 0.35) * 0.045 + this.mouse.x * 0.22;
      this.sculptureGroup.rotation.z = this.baseRotZ + Math.sin(time * 0.25) * 0.02;

      // Subtle float displacement
      this.sculptureGroup.position.x = this.basePosX + this.mouse.x * 1.2;
      this.sculptureGroup.position.y = this.basePosY + Math.sin(time * 0.6) * 0.18 - this.mouse.y * 0.8;
    }

    // 3. Subtle inner core light pulsing
    if (this.innerMintLight) {
      this.innerMintLight.intensity = 5.8 + Math.sin(time * 1.8) * 0.7;
    }

    // 4. Stardust drift
    if (this.particles) {
      this.particles.rotation.y += 0.0003;
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
    document.removeEventListener('visibilitychange', this.onVisibilityChange);
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
